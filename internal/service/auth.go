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

// UpdateUser 修改账号角色或状态。
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
func (s *Service) ChangePassword(ctx context.Context, id int64, oldPw, newPw string, a Actor) error {
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
	s.audit(ctx, a, "user.change_password", "user", fmt.Sprint(id), "", "", "ok", "")
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
}

// TOTPRequired 表示是否还需要二次验证。
func (r *LoginStep) TOTPRequired() bool { return r.Challenge != "" }

// hashToken 是会话令牌与挑战令牌统一的落库形式：只存 SHA-256，不存明文。
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Login 校验口令。
//
// 账号开启二次验证时**不签发会话**，只返回一次性挑战；调用方需再调用
// CompleteTOTPLogin 提交动态口令，通过后才真正登录。
func (s *Service) Login(ctx context.Context, username, password, ua, ip string) (*LoginStep, error) {
	u, err := s.Store.GetUserByUsername(ctx, strings.TrimSpace(username))
	if err != nil {
		s.audit(ctx, Actor{Username: username, SrcIP: ip}, "auth.login", "user", username, "", "", "deny", "账号不存在")
		return nil, errors.New("用户名或密码错误")
	}
	if u.Status != 1 {
		return nil, errors.New("该账号已被停用，请联系管理员")
	}
	if !VerifyPassword(password, u.PasswordHash) {
		s.audit(ctx, Actor{UserID: u.ID, Username: u.Username, SrcIP: ip}, "auth.login", "user", fmt.Sprint(u.ID), "", "", "deny", "密码错误")
		return nil, errors.New("用户名或密码错误")
	}
	if u.TOTPSecret != "" {
		ch := newToken(32)
		if err := s.Store.CreateTOTPChallenge(ctx, hashToken(ch), u.ID, time.Now().Add(totpChallengeTTL)); err != nil {
			return nil, err
		}
		s.audit(ctx, Actor{UserID: u.ID, Username: u.Username, SrcIP: ip}, "auth.login", "user", fmt.Sprint(u.ID), "", "", "ok", "口令已通过，等待二次验证")
		return &LoginStep{Challenge: ch}, nil
	}
	return s.issueSession(ctx, u, ua, ip)
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
