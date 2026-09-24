// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package service

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"fnwg/internal/model"
	"fnwg/internal/store"
)

// placeholderPassword 是飞牛身份账号的口令散列占位值。
//
// 它**必须是格式非法的**：VerifyPassword 一见格式不对就返回 false，
// 于是这类账号永远不可能用密码登录。这条性质来自校验逻辑本身，
// 不依赖「登录时记得多判断一次来源」这种容易漏的写法。
const placeholderPassword = "!飞牛身份账号没有口令"

// gatewayFallbackName 是拿不到可用飞牛用户名时的兜底账号名。
//
// **对应关系永远按 UID 走**（trim_uid 字段），账号名只是给人看的：
// 早先版本把账号名做成 nas:<uid>，用户看着像机器编号，不该这样。
const gatewayFallbackName = "fnos-"

// GatewayUsername 生成一个可用的账号名：优先用飞牛用户名，实在拿不到才用用户名兜底。
//
// 注意：**这里生成的只是「给人看的账号名」，不是身份键**。身份键始终是 UID ——
// 若按名字匹配，一个叫 admin 的飞牛普通用户会直接对上本地管理员账号，那是提权漏洞。
// 重名时由 EnsureGatewayUser 加数字后缀，绝不覆盖已有账号。
func GatewayUsername(uid int64, name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return gatewayFallbackName + strconv.FormatInt(uid, 10)
	}
	return name
}

// EnsureGatewayUser 把一次「网关注入的飞牛身份」映射成本应用账号，必要时创建并同步角色。
//
// 它每次请求都会被调用（网关通道是无状态的），所以这里只做三件必要的事：
//   - 账号不存在 → 建一个（首次进入时惰性创建）；
//   - 角色与飞牛侧不一致 → 跟着改（飞牛侧撤权后，本应用必须立刻降权，不能等会话过期）；
//   - 账号被停用 → 拒绝（管理员在本应用里停用一个飞牛账号，就应当立刻生效）。
//
// 用户名只作展示快照，**永不参与匹配**。
func (s *Service) EnsureGatewayUser(ctx context.Context, uid int64, name string, isAdmin bool) (*model.User, error) {
	if uid <= 0 {
		return nil, errors.New("飞牛身份缺少有效的用户 ID")
	}
	role := model.RoleViewer
	if isAdmin {
		role = model.RoleAdmin
	}
	name = strings.TrimSpace(name)

	u, err := s.Store.GetUserByTrimUID(ctx, uid)
	if errors.Is(err, store.ErrNotFound) {
		// 账号名优先用飞牛用户名；被占用时加后缀 —— 同名冲突（尤其与本地 admin 同名）
		// 绝不能去覆盖或复用别人的账号，只能另起一个名字。
		username, uerr := s.Store.FreeUsername(ctx, GatewayUsername(uid, name), strconv.FormatInt(uid, 10))
		if uerr != nil {
			return nil, uerr
		}
		nu, cerr := s.Store.CreateGatewayUser(ctx, uid, username, name, placeholderPassword, role)
		if cerr != nil {
			// 两个请求同时首次进入时，唯一索引会拦下后一个：此时直接读回对方建好的那条，
			// 而不是把一次并发当成错误报给用户。
			if again, e2 := s.Store.GetUserByTrimUID(ctx, uid); e2 == nil {
				return again, nil
			}
			return nil, cerr
		}
		s.audit(ctx, Actor{Username: "gateway"}, "user.create", "user", fmt.Sprint(nu.ID), "",
			nu.Username+"/"+role, "ok", "飞牛账号首次通过统一网关进入，自动创建")
		return nu, nil
	}
	if err != nil {
		return nil, err
	}

	if u.Status != 1 {
		return nil, errors.New("该账号已被停用")
	}
	// 展示名跟着飞牛侧走（用户可能在飞牛里改过名）；角色跟随则关系到权限，两者都要同步。
	// 只在真变了才写库：网关通道每次请求都会走到这里，没必要为了写回同样的值而天天写。
	oldRole := u.Role
	roleChanged := u.Role != role
	nameChanged := u.TrimName != name
	if roleChanged || nameChanged {
		u.Role, u.TrimName = role, name
		if err := s.Store.UpdateUser(ctx, u); err != nil {
			return nil, err
		}
	}
	if roleChanged {
		s.audit(ctx, Actor{Username: "gateway"}, "user.role", "user", fmt.Sprint(u.ID), oldRole, role, "ok",
			"跟随飞牛账号的角色变化")
	}
	return u, nil
}

// LoginAsGatewayUser 为「凭飞牛身份进来」的请求换发一个**普通会话**。
//
// 为什么不直接按请求头每次放行（早先那版就是那样）：身份头每个请求都会带上，
// 于是「退出登录」等于「下一刻又被带进来」（真机反馈），而且没有会话就没有来源、没有可注销的东西。
// 改成显式换发会话之后：退出是真退出，审计与来源 IP 与账号密码登录走同一套。
func (s *Service) LoginAsGatewayUser(ctx context.Context, uid int64, name string, isAdmin bool, ua, ip string) (*LoginStep, error) {
	u, err := s.EnsureGatewayUser(ctx, uid, name, isAdmin)
	if err != nil {
		return nil, err
	}
	return s.issueSession(ctx, u, ua, ip)
}
