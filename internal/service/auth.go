// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 newcdl <newcdl@163.com>

package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"

	"fnwg/internal/model"
	"fnwg/internal/store"
)

const (
	sessionTTL   = 7 * 24 * time.Hour
	argonTime    = 1
	argonMemory  = 64 * 1024
	argonThreads = 4
	argonKeyLen  = 32
)

// HashPassword 生成 argon2id 口令散列。
func HashPassword(pw string) (string, error) {
	if len(pw) < 8 {
		return "", errors.New("密码长度至少 8 位")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword 校验口令。
func VerifyPassword(pw, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 || parts[0] != "argon2id" {
		return false
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[2], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(pw), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// HasUsers 判断是否已初始化管理员。
func (s *Service) HasUsers(ctx context.Context) (bool, error) {
	n, err := s.Store.CountUsers(ctx)
	return n > 0, err
}

// Setup 创建首个管理员账号（仅在无任何账号时可用）。
func (s *Service) Setup(ctx context.Context, username, password string) (*model.User, error) {
	n, err := s.Store.CountUsers(ctx)
	if err != nil {
		return nil, err
	}
	if n > 0 {
		return nil, errors.New("系统已初始化，请直接登录")
	}
	return s.CreateUser(ctx, username, password, model.RoleAdmin, Actor{Username: "setup"})
}

// CreateUser 创建账号。
func (s *Service) CreateUser(ctx context.Context, username, password, role string, a Actor) (*model.User, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return nil, errors.New("用户名不能为空")
	}

	switch role {
	case model.RoleAdmin, model.RoleOperator, model.RoleViewer:
	default:
		return nil, errors.New("角色不合法")
	}
	hash, err := HashPassword(password)
	if err != nil {
		return nil, err
	}
	u := &model.User{Username: username, PasswordHash: hash, Role: role, Status: 1}
	if err := s.Store.CreateUser(ctx, u); err != nil {
		return nil, fmt.Errorf("创建账号失败（用户名可能已存在）: %w", err)
	}
	s.audit(ctx, a, "user.create", "user", fmt.Sprint(u.ID), "", username+"/"+role, "ok", "")
	return u, nil
}

// ListUsers 返回账号列表。
func (s *Service) ListUsers(ctx context.Context) ([]model.User, error) {
	return s.Store.ListUsers(ctx)
}

// UpdateUser 修改账号角色或状态（管理员操作）。
func (s *Service) UpdateUser(ctx context.Context, id int64, role string, status int, password string, a Actor) error {
	u, err := s.Store.GetUser(ctx, id)
	if err != nil {
		return err
	}
	if role != "" {
		u.Role = role
	}
	if status == 0 || status == 1 {
		u.Status = status
	}
	if password != "" {
		h, err := HashPassword(password)
		if err != nil {
			return err
		}
		u.PasswordHash = h
	}
	if err := s.Store.UpdateUser(ctx, u); err != nil {
		return err
	}
	// 管理员改掉了别人的口令后，该账号的在线会话与「免二次验证」资格都必须收回：
	// 否则知道旧口令的人可能仍留在系统里，而受信任设备更是直接绕过二次验证。
	// 这与官方 2FA「重置密码后自动登出该用户所有设备」的语义一致。
	if password != "" {
		_ = s.Store.DeleteUserSessions(ctx, id)
		_ = s.Store.DeleteAllTrustedDevices(ctx, id)
	}
	s.audit(ctx, a, "user.update", "user", fmt.Sprint(id), "", u.Username+"/"+u.Role, "ok", "")
	return nil
}

// DeleteUser 删除账号（不允许删除最后一个管理员）。
func (s *Service) DeleteUser(ctx context.Context, id int64, a Actor) error {
	u, err := s.Store.GetUser(ctx, id)
	if err != nil {
		return err
	}
	if u.Role == model.RoleAdmin {
		users, _ := s.Store.ListUsers(ctx)
		admins := 0
		for _, x := range users {
			if x.Role == model.RoleAdmin && x.Status == 1 {
				admins++
			}
		}
		if admins <= 1 {
			return errors.New("至少需要保留一个启用的管理员账号")
		}
	}
	if err := s.Store.DeleteUser(ctx, id); err != nil {
		return err
	}
	s.audit(ctx, a, "user.delete", "user", fmt.Sprint(id), u.Username, "", "ok", "")
	return nil
}

// ChangePassword 修改自己的口令。
//
// 改完口令必须做两件事，缺一不可（官方 2FA 的语义也是如此）：
//  1. 作废本账号全部受信任设备——否则改密码收不回别人设备上「免二次验证」的资格；
//  2. 登出除当前会话外的所有会话——把可能已经泄露的旧会话清掉，
//     同时不把正在操作的这个浏览器踢出去（currentToken 为空时才全清）。
func (s *Service) ChangePassword(ctx context.Context, id int64, oldPw, newPw, currentToken string, a Actor) error {
	u, err := s.Store.GetUser(ctx, id)
	if err != nil {
		return err
	}
	if !VerifyPassword(oldPw, u.PasswordHash) {
		s.audit(ctx, a, "user.change_password", "user", fmt.Sprint(id), "", "", "deny", "原密码错误")
		return errors.New("原密码错误")
	}
	h, err := HashPassword(newPw)
	if err != nil {
		return err
	}
	u.PasswordHash = h
	if err := s.Store.UpdateUser(ctx, u); err != nil {
		return err
	}
	if err := s.Store.DeleteAllTrustedDevices(ctx, id); err != nil {
		return err
	}
	if currentToken != "" {
		_ = s.Store.DeleteOtherSessions(ctx, id, hashToken(currentToken))
	} else {
		_ = s.Store.DeleteUserSessions(ctx, id)
	}
	s.audit(ctx, a, "user.change_password", "user", fmt.Sprint(id), "", "", "ok", "已作废受信任设备并登出其它会话")
	return nil
}

// LoginStep 是一次登录尝试的结果。
//
// 两项恰有其一：Challenge 非空表示「口令已通过，但还需二次验证」，
// 此时**不签发任何会话**；否则 Token/User 就是已完成登录的会话。
type LoginStep struct {
	Token     string
	User      *model.User
	Challenge string
	// DeviceToken / DeviceExpiresAt 仅在勾选「信任本设备」并校验通过后才有值，
	// 明文令牌只在这里返回一次，落库存的是哈希。
	DeviceToken     string
	DeviceExpiresAt time.Time
}

// TOTPRequired 表示是否还需要二次验证。
func (r *LoginStep) TOTPRequired() bool { return r.Challenge != "" }

// LoginInput 是一次登录尝试的全部输入。
//
// 刻意收成结构体而不是参数列表：这里同时有 username / password / deviceToken /
// userAgent / ip 五个字符串，位置写错编译器不会拦，而那等于「拿别人的设备令牌登录」。
type LoginInput struct {
	Username    string
	Password    string
	DeviceToken string // 受信任设备令牌；命中且有效则跳过二次验证
	UserAgent   string
	SrcIP       string
}

// hashToken 是会话令牌、挑战令牌与设备令牌统一的落库形式：只存 SHA-256，不存明文。
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Login 校验口令。
//
// 账号开启二次验证时**不签发会话**，只返回一次性挑战；调用方需再调用
// CompleteTOTPLogin 提交动态口令，通过后才真正登录。
// 例外：来自「已信任设备」的登录可以直接拿到会话（等价于官方 2FA 的信任本设备）。
func (s *Service) Login(ctx context.Context, in LoginInput) (*LoginStep, error) {
	u, err := s.Store.GetUserByUsername(ctx, strings.TrimSpace(in.Username))
	if err != nil {
		s.audit(ctx, Actor{Username: in.Username, SrcIP: in.SrcIP}, "auth.login", "user", in.Username, "", "", "deny", "账号不存在")
		return nil, errors.New("用户名或密码错误")
	}
	if u.Status != 1 {
		return nil, errors.New("该账号已被停用，请联系管理员")
	}
	if !VerifyPassword(in.Password, u.PasswordHash) {
		s.audit(ctx, Actor{UserID: u.ID, Username: u.Username, SrcIP: in.SrcIP}, "auth.login", "user", fmt.Sprint(u.ID), "", "", "deny", "密码错误")
		return nil, errors.New("用户名或密码错误")
	}
	if u.TOTPSecret != "" {
		if s.trustedDeviceOK(ctx, u, in.DeviceToken, in.SrcIP) {
			return s.issueSession(ctx, u, in.UserAgent, in.SrcIP)
		}
		ch := newToken(32)
		if err := s.Store.CreateTOTPChallenge(ctx, hashToken(ch), u.ID, time.Now().Add(totpChallengeTTL)); err != nil {
			return nil, err
		}
		s.audit(ctx, Actor{UserID: u.ID, Username: u.Username, SrcIP: in.SrcIP}, "auth.login", "user", fmt.Sprint(u.ID), "", "", "ok", "口令已通过，等待二次验证")
		return &LoginStep{Challenge: ch}, nil
	}
	return s.issueSession(ctx, u, in.UserAgent, in.SrcIP)
}

// trustedDeviceOK 判断设备令牌能否用于跳过二次验证。
//
// 三重校验缺一不可：令牌存在且未过期、令牌属于当前账号、
// **该账号当前确实开着二次验证**。最后一条最容易被忽略——少了它，
// 关闭二次验证后残留的令牌会在重新开启时自动复活成后门。
func (s *Service) trustedDeviceOK(ctx context.Context, u *model.User, deviceToken, ip string) bool {
	token := strings.TrimSpace(deviceToken)
	if token == "" || u.TOTPSecret == "" {
		return false
	}
	d, err := s.Store.GetTrustedDevice(ctx, hashToken(token))
	if err != nil || d.UserID != u.ID {
		return false
	}
	_ = s.Store.TouchTrustedDevice(ctx, d.ID)
	s.audit(ctx, Actor{UserID: u.ID, Username: u.Username, SrcIP: ip}, "auth.login.totp", "user",
		fmt.Sprint(u.ID), "", "", "ok", "受信任设备，免动态口令")
	return true
}

// issueSession 为已通过全部校验的账号签发会话。
func (s *Service) issueSession(ctx context.Context, u *model.User, ua, ip string) (*LoginStep, error) {
	token := newToken(32)
	sess := &model.Session{
		TokenHash: hashToken(token),
		UserID:    u.ID,
		ExpiresAt: time.Now().Add(sessionTTL),
		UserAgent: ua,
		SrcIP:     ip,
	}
	if err := s.Store.CreateSession(ctx, sess); err != nil {
		return nil, err
	}
	_ = s.Store.TouchLastLogin(ctx, u.ID)
	s.audit(ctx, Actor{UserID: u.ID, Username: u.Username, SrcIP: ip}, "auth.login", "user", fmt.Sprint(u.ID), "", "", "ok", "")
	return &LoginStep{Token: token, User: u}, nil
}

// Logout 注销会话。
func (s *Service) Logout(ctx context.Context, token string) error {
	return s.Store.DeleteSession(ctx, hashToken(token))
}

// Authenticate 校验令牌并返回账号。
//
// 会话账号通往界面的两条出口（登录响应、以及这里的 /auth/me 与 /auth/state）
// 现在都直接读库，因此两处拿到的必然是同一份数据。早先这里还要补一层「来源与展示名」
// 的派生，是为了让飞牛账号显示成用户认得出来的名字 —— 那套派生已随免密登录一并移除，
// 现在没有任何字段需要在多处补齐，也就不会再出现「登录那一刻与刷新之后名字不一样」。
func (s *Service) Authenticate(ctx context.Context, token string) (*model.User, error) {
	if token == "" {
		return nil, errors.New("未登录")
	}
	sess, u, err := s.Store.GetSession(ctx, hashToken(token))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, errors.New("登录状态已失效，请重新登录")
		}
		return nil, err
	}
	if sess == nil || u.Status != 1 {
		return nil, errors.New("账号不可用")
	}
	return u, nil
}
