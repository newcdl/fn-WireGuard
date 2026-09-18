// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package service

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"strings"

	"fnwg/internal/model"
	"fnwg/internal/store"
)

// securityCodeBytes 是安全码的随机字节数：32 字节 = 256 位熵。
const securityCodeBytes = 32

// securityCodeEncodedLen 是 Base32（无 padding）编码后的字符数：32 字节 → 52 个字符。
const securityCodeEncodedLen = (securityCodeBytes*8 + 4) / 5

// securityCodeEncoding 用 RFC 4648 标准 Base32、无 padding。
var securityCodeEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateSecurityCode 生成一枚新的安全码明文。
//
// 32 字节随机 → 52 个 Base32 字符，约 256 位熵：即使拿到哈希做离线爆破也不可能猜中。
// 这正是它能充当「最后的万能钥匙」的前提——它绕过口令与二次验证，
// 强度必须高到「猜不出来」这一条就足够，而不依赖任何限流。
func GenerateSecurityCode() (string, error) {
	buf := make([]byte, securityCodeBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return securityCodeEncoding.EncodeToString(buf), nil
}

// NormalizeSecurityCode 规整用户输入：忽略大小写、分组连字符与所有空白。
//
// 安全码是 52 个字符的长串，用户多半是从密码管理器复制、或从纸上分组抄录的，
// 带上连字符、空格或大小写变化都很常见，规整后再比对才不会「明明抄对了却进不去」。
func NormalizeSecurityCode(code string) string {
	var sb strings.Builder
	for _, r := range strings.ToUpper(strings.TrimSpace(code)) {
		switch r {
		case '-', ' ', '\t', '\n', '\r':
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

// GroupSecurityCode 把安全码按 5 个字符一组展示，长串更易抄录与核对。
func GroupSecurityCode(code string) string {
	parts := make([]string, 0, len(code)/5+1)
	for i := 0; i < len(code); i += 5 {
		end := i + 5
		if end > len(code) {
			end = len(code)
		}
		parts = append(parts, code[i:end])
	}
	return strings.Join(parts, "-")
}

// SecurityCodeConfigured 返回当前是否已设置安全码。
func (s *Service) SecurityCodeConfigured(ctx context.Context) (bool, error) {
	if _, err := s.Store.GetSecurityCode(ctx); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// IssueSecurityCode 生成、保存并返回一枚新的安全码（明文仅此一次）。
//
// 落库走 SetSecurityCode，它会先清空旧码——所以「重新生成」天然等于「旧码立即作废」。
func (s *Service) IssueSecurityCode(ctx context.Context, a Actor) (string, error) {
	code, err := GenerateSecurityCode()
	if err != nil {
		return "", err
	}
	h, err := HashPassword(code)
	if err != nil {
		return "", err
	}
	if err := s.Store.SetSecurityCode(ctx, h); err != nil {
		return "", err
	}
	s.audit(ctx, a, "security.code_issue", "user", "", "", "", "ok", "生成了新的安全码（旧码已作废）")
	return code, nil
}

// EmergencyResult 是应急登录的返回。
type EmergencyResult struct {
	// Token 是本次签发的会话令牌，由调用方写进 Cookie，不出现在响应体里。
	Token string      `json:"-"`
	User  *model.User `json:"user"`
	// NewCode 是替换后的新安全码：旧码在本次登录中已被消耗，这是唯一一次展示机会。
	NewCode string `json:"new_code"`
}

// EmergencyLogin 用安全码应急登录——所有常规途径都失效时的最后入口。
//
// 设计的四条要点：
//  1. 安全码**一次性**：校验通过后立刻作废并下发新的，避免留下一把长期有效的万能钥匙；
//  2. 登录后落到「第一个启用的管理员」身上，否则拿到会话也做不了恢复动作；
//  3. 可选同时重置该管理员的口令，一步把控制权收回来（此时按既有安全约束，
//     一并作废其受信任设备与其它会话）；
//  4. 成功与失败都审计留痕——这是最高权限的入口，必须可追溯。
func (s *Service) EmergencyLogin(ctx context.Context, code, newPassword, ua, ip string, a Actor) (*EmergencyResult, error) {
	norm := NormalizeSecurityCode(code)
	if len(norm) != securityCodeEncodedLen {
		s.audit(ctx, a, "security.emergency_login", "user", "", "", "", "deny", "安全码长度不正确")
		return nil, errors.New("安全码不正确")
	}
	hash, err := s.Store.GetSecurityCode(ctx)
	if err != nil {
		return nil, errors.New("未设置安全码，应急登录不可用")
	}
	if !VerifyPassword(norm, hash) {
		s.audit(ctx, a, "security.emergency_login", "user", "", "", "", "deny", "安全码错误")
		return nil, errors.New("安全码不正确")
	}
	admin, err := s.firstEnabledAdmin(ctx)
	if err != nil {
		return nil, err
	}
	if newPassword != "" {
		h, err := HashPassword(newPassword)
		if err != nil {
			return nil, err
		}
		admin.PasswordHash = h
		if err := s.Store.UpdateUser(ctx, admin); err != nil {
			return nil, err
		}
		// 与「改密码」保持同一条安全约束：作废受信任设备、清掉其它会话。
		_ = s.Store.DeleteAllTrustedDevices(ctx, admin.ID)
		_ = s.Store.DeleteUserSessions(ctx, admin.ID)
	}
	// 旧码即刻作废，并下发新码（IssueSecurityCode 内部会先清空旧记录）
	newCode, err := s.IssueSecurityCode(ctx, a)
	if err != nil {
		return nil, err
	}
	step, err := s.issueSession(ctx, admin, ua, ip)
	if err != nil {
		return nil, err
	}
	detail := "已通过安全码应急登录"
	if newPassword != "" {
		detail += "，并重置了管理员口令"
	}
	s.audit(ctx, Actor{UserID: admin.ID, Username: admin.Username, SrcIP: ip},
		"security.emergency_login", "user", admin.Username, "", "", "ok", detail)
	return &EmergencyResult{Token: step.Token, User: admin, NewCode: newCode}, nil
}

// firstEnabledAdmin 返回第一个启用的管理员账号，应急登录就落在它身上。
//
// 之所以要「启用的管理员」：拿到会话的目的就是做恢复动作，
// 落在一个被停用的账号上等于白进。
func (s *Service) firstEnabledAdmin(ctx context.Context) (*model.User, error) {
	users, err := s.Store.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	for i := range users {
		if users[i].Role == model.RoleAdmin && users[i].Status == 1 {
			return &users[i], nil
		}
	}
	return nil, errors.New("没有可用的管理员账号，请先完成初始化")
}
