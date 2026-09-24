// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"fnwg/internal/model"
)

// ---------------------------------------------------------------- 用户

// CountUsers 返回账号数量，用于判断是否需要初始化管理员。
func (s *Store) CountUsers(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM sys_user`).Scan(&n)
	return n, err
}

// CreateUser 新建账号。
func (s *Store) CreateUser(ctx context.Context, u *model.User) error {
	if u.Role == "" {
		u.Role = model.RoleViewer
	}
	now := time.Now()
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO sys_user(username,password_hash,totp_secret,role,status,created_at) VALUES(?,?,?,?,?,?)`,
		u.Username, u.PasswordHash, u.TOTPSecret, u.Role, u.Status, ts(now))
	if err != nil {
		return err
	}
	u.ID, _ = res.LastInsertId()
	u.CreatedAt = now
	return nil
}

func (s *Store) scanUser(sc interface{ Scan(...any) error }) (*model.User, error) {
	var (
		u           model.User
		lastLoginAt sql.NullString
		createdAt   string
	)
	if err := sc.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.TOTPSecret, &u.Role, &u.Status, &lastLoginAt, &createdAt, &u.TrimUID, &u.TrimName); err != nil {
		return nil, err
	}
	u.LastLoginAt = parseTSNull(lastLoginAt)
	u.CreatedAt = parseTS(createdAt)
	u.TOTPEnabled = u.TOTPSecret != ""
	return &u, nil
}

// ListUsers 返回全部账号。
func (s *Store) ListUsers(ctx context.Context) ([]model.User, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,username,password_hash,totp_secret,role,status,last_login_at,created_at,COALESCE(trim_uid,0),COALESCE(trim_name,'') FROM sys_user ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.User{}
	for rows.Next() {
		u, err := s.scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

// GetUserByUsername 按用户名查询。
func (s *Store) GetUserByUsername(ctx context.Context, username string) (*model.User, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id,username,password_hash,totp_secret,role,status,last_login_at,created_at,COALESCE(trim_uid,0),COALESCE(trim_name,'') FROM sys_user WHERE username=?`, username)
	u, err := s.scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return u, err
}

// GetUser 按主键查询。
func (s *Store) GetUser(ctx context.Context, id int64) (*model.User, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id,username,password_hash,totp_secret,role,status,last_login_at,created_at,COALESCE(trim_uid,0),COALESCE(trim_name,'') FROM sys_user WHERE id=?`, id)
	u, err := s.scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return u, err
}

// UpdateUser 更新账号基本信息。
func (s *Store) UpdateUser(ctx context.Context, u *model.User) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE sys_user SET password_hash=?,totp_secret=?,role=?,status=?,trim_name=? WHERE id=?`,
		u.PasswordHash, u.TOTPSecret, u.Role, u.Status, u.TrimName, u.ID)
	return err
}

// DeleteUser 删除账号。
func (s *Store) DeleteUser(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sys_user WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// TouchLastLogin 记录最近登录时间。
func (s *Store) TouchLastLogin(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sys_user SET last_login_at=? WHERE id=?`, ts(time.Now()), id)
	return err
}

// ---------------------------------------------------------------- 会话

// CreateSession 写入会话。
func (s *Store) CreateSession(ctx context.Context, sess *model.Session) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sys_session(token_hash,user_id,expires_at,created_at,user_agent,src_ip) VALUES(?,?,?,?,?,?)`,
		sess.TokenHash, sess.UserID, ts(sess.ExpiresAt), ts(time.Now()), sess.UserAgent, sess.SrcIP)
	return err
}

// GetSession 查询未过期会话，并返回对应账号。
func (s *Store) GetSession(ctx context.Context, tokenHash string) (*model.Session, *model.User, error) {
	var (
		sess      model.Session
		expiresAt string
		createdAt string
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT token_hash,user_id,expires_at,created_at,user_agent,src_ip FROM sys_session WHERE token_hash=?`, tokenHash).
		Scan(&sess.TokenHash, &sess.UserID, &expiresAt, &createdAt, &sess.UserAgent, &sess.SrcIP)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, ErrNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	sess.ExpiresAt = parseTS(expiresAt)
	sess.CreatedAt = parseTS(createdAt)
	if time.Now().After(sess.ExpiresAt) {
		_ = s.DeleteSession(ctx, tokenHash)
		return nil, nil, ErrNotFound
	}
	u, err := s.GetUser(ctx, sess.UserID)
	if err != nil {
		return nil, nil, err
	}
	return &sess, u, nil
}

// DeleteSession 注销会话。
func (s *Store) DeleteSession(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sys_session WHERE token_hash=?`, tokenHash)
	return err
}

// CleanExpiredSessions 清理过期会话。
func (s *Store) CleanExpiredSessions(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sys_session WHERE expires_at < ?`, ts(time.Now()))
	return err
}

// ---------------------------------------------------------------- 二次验证

// CreateTOTPChallenge 写入一次二次验证挑战。
func (s *Store) CreateTOTPChallenge(ctx context.Context, tokenHash string, userID int64, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sys_totp_challenge(token_hash,user_id,expires_at,created_at) VALUES(?,?,?,?)`,
		tokenHash, userID, ts(expiresAt), ts(time.Now()))
	return err
}

// GetTOTPChallenge 查询未过期的挑战；过期即删除并按「不存在」返回。
func (s *Store) GetTOTPChallenge(ctx context.Context, tokenHash string) (*model.TOTPChallenge, error) {
	var (
		c         model.TOTPChallenge
		expiresAt string
		createdAt string
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT token_hash,user_id,expires_at,attempts,created_at FROM sys_totp_challenge WHERE token_hash=?`, tokenHash).
		Scan(&c.TokenHash, &c.UserID, &expiresAt, &c.Attempts, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	c.ExpiresAt = parseTS(expiresAt)
	c.CreatedAt = parseTS(createdAt)
	if time.Now().After(c.ExpiresAt) {
		_ = s.DeleteTOTPChallenge(ctx, tokenHash)
		return nil, ErrNotFound
	}
	return &c, nil
}

// BumpTOTPChallengeAttempts 累加失败次数并返回最新值，用于限制单次挑战的尝试次数。
func (s *Store) BumpTOTPChallengeAttempts(ctx context.Context, tokenHash string) (int, error) {
	if _, err := s.db.ExecContext(ctx,
		`UPDATE sys_totp_challenge SET attempts=attempts+1 WHERE token_hash=?`, tokenHash); err != nil {
		return 0, err
	}
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT attempts FROM sys_totp_challenge WHERE token_hash=?`, tokenHash).Scan(&n)
	return n, err
}

// DeleteTOTPChallenge 删除挑战。验证成功后必须调用，保证挑战只能用一次。
func (s *Store) DeleteTOTPChallenge(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sys_totp_challenge WHERE token_hash=?`, tokenHash)
	return err
}

// CleanExpiredTOTPChallenges 清理过期挑战。
func (s *Store) CleanExpiredTOTPChallenges(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sys_totp_challenge WHERE expires_at < ?`, ts(time.Now()))
	return err
}

// SetUserTOTPSecret 写入二次验证密钥（开启二次验证时调用）。
func (s *Store) SetUserTOTPSecret(ctx context.Context, userID int64, secret string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sys_user SET totp_secret=? WHERE id=?`, secret, userID)
	return err
}

// ClearUserTOTP 关闭 / 重置二次验证：清空密钥、删除恢复码与受信任设备，
// 并顺手清掉该账号未完成的挑战。
//
// 受信任设备必须一起删：它本身就是「跳过二次验证」的凭据，留着它就等于
// 二次验证虽然关了但后门还在，而且重新开启后这个后门会自动复活。
func (s *Store) ClearUserTOTP(ctx context.Context, userID int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []string{
		`UPDATE sys_user SET totp_secret='' WHERE id=?`,
		`DELETE FROM sys_recovery_code WHERE user_id=?`,
		`DELETE FROM sys_totp_challenge WHERE user_id=?`,
		`DELETE FROM sys_trusted_device WHERE user_id=?`,
	} {
		if _, err := tx.ExecContext(ctx, q, userID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ReplaceRecoveryCodes 用新一批恢复码哈希整体替换旧记录。
func (s *Store) ReplaceRecoveryCodes(ctx context.Context, userID int64, hashes []string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM sys_recovery_code WHERE user_id=?`, userID); err != nil {
		return err
	}
	now := ts(time.Now())
	for _, h := range hashes {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO sys_recovery_code(user_id,code_hash,created_at) VALUES(?,?,?)`, userID, h, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ListUnusedRecoveryCodes 返回某账号尚未使用过的恢复码（只含哈希）。
func (s *Store) ListUnusedRecoveryCodes(ctx context.Context, userID int64) ([]model.RecoveryCode, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,user_id,code_hash,created_at FROM sys_recovery_code WHERE user_id=? AND used_at IS NULL ORDER BY id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.RecoveryCode{}
	for rows.Next() {
		var (
			c         model.RecoveryCode
			createdAt string
		)
		if err := rows.Scan(&c.ID, &c.UserID, &c.CodeHash, &createdAt); err != nil {
			return nil, err
		}
		c.CreatedAt = parseTS(createdAt)
		out = append(out, c)
	}
	return out, rows.Err()
}

// MarkRecoveryCodeUsed 标记恢复码已使用（恢复码是一次性的）。
func (s *Store) MarkRecoveryCodeUsed(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sys_recovery_code SET used_at=? WHERE id=?`, ts(time.Now()), id)
	return err
}

// CountUnusedRecoveryCodes 统计剩余可用恢复码数量。
func (s *Store) CountUnusedRecoveryCodes(ctx context.Context, userID int64) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(1) FROM sys_recovery_code WHERE user_id=? AND used_at IS NULL`, userID).Scan(&n)
	return n, err
}

// ---------------------------------------------------------------- 受信任设备

// CreateTrustedDevice 记录一台受信任设备（tokenHash 是设备令牌的 SHA-256）。
func (s *Store) CreateTrustedDevice(ctx context.Context, d *model.TrustedDevice) error {
	now := time.Now()
	if d.CreatedAt.IsZero() {
		d.CreatedAt = now
	}
	if d.LastUsedAt.IsZero() {
		d.LastUsedAt = now
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO sys_trusted_device(user_id,token_hash,name,src_ip,created_at,last_used_at,expires_at) VALUES(?,?,?,?,?,?,?)`,
		d.UserID, d.TokenHash, d.Name, d.SrcIP, ts(d.CreatedAt), ts(d.LastUsedAt), ts(d.ExpiresAt))
	if err != nil {
		return err
	}
	d.ID, _ = res.LastInsertId()
	return nil
}

// GetTrustedDevice 按令牌哈希查询；已过期即删除并按「不存在」返回。
func (s *Store) GetTrustedDevice(ctx context.Context, tokenHash string) (*model.TrustedDevice, error) {
	var (
		d          model.TrustedDevice
		createdAt  string
		lastUsedAt string
		expiresAt  string
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT id,user_id,token_hash,name,src_ip,created_at,last_used_at,expires_at FROM sys_trusted_device WHERE token_hash=?`, tokenHash).
		Scan(&d.ID, &d.UserID, &d.TokenHash, &d.Name, &d.SrcIP, &createdAt, &lastUsedAt, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	d.CreatedAt = parseTS(createdAt)
	d.LastUsedAt = parseTS(lastUsedAt)
	d.ExpiresAt = parseTS(expiresAt)
	if time.Now().After(d.ExpiresAt) {
		_ = s.DeleteTrustedDeviceByID(ctx, d.ID)
		return nil, ErrNotFound
	}
	return &d, nil
}

// TouchTrustedDevice 更新最近使用时间，便于用户在列表里识别哪台在用。
func (s *Store) TouchTrustedDevice(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sys_trusted_device SET last_used_at=? WHERE id=?`, ts(time.Now()), id)
	return err
}

// ListTrustedDevices 返回某账号的全部受信任设备（不含令牌哈希）。
func (s *Store) ListTrustedDevices(ctx context.Context, userID int64) ([]model.TrustedDevice, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,user_id,name,src_ip,created_at,last_used_at,expires_at FROM sys_trusted_device WHERE user_id=? ORDER BY id DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.TrustedDevice{}
	for rows.Next() {
		var (
			d          model.TrustedDevice
			createdAt  string
			lastUsedAt string
			expiresAt  string
		)
		if err := rows.Scan(&d.ID, &d.UserID, &d.Name, &d.SrcIP, &createdAt, &lastUsedAt, &expiresAt); err != nil {
			return nil, err
		}
		d.CreatedAt = parseTS(createdAt)
		d.LastUsedAt = parseTS(lastUsedAt)
		d.ExpiresAt = parseTS(expiresAt)
		out = append(out, d)
	}
	return out, rows.Err()
}

// DeleteTrustedDevice 撤销一台受信任设备。带 userID 条件是为了防越权：
// 即使 id 猜对了，也只能删自己的设备。
func (s *Store) DeleteTrustedDevice(ctx context.Context, userID, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sys_trusted_device WHERE id=? AND user_id=?`, id, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteTrustedDeviceByID 按主键删除（内部清理过期记录用，不做属主校验）。
func (s *Store) DeleteTrustedDeviceByID(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sys_trusted_device WHERE id=?`, id)
	return err
}

// DeleteAllTrustedDevices 清空某账号的全部受信任设备。
//
// 改密码、切换二次验证开关、管理员重置后都必须调用它。
func (s *Store) DeleteAllTrustedDevices(ctx context.Context, userID int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sys_trusted_device WHERE user_id=?`, userID)
	return err
}

// CleanExpiredTrustedDevices 清理已过期的受信任设备。
func (s *Store) CleanExpiredTrustedDevices(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sys_trusted_device WHERE expires_at < ?`, ts(time.Now()))
	return err
}

// DeleteOtherSessions 删除该账号除指定会话外的全部会话（改密码后把其它设备踢下线）。
func (s *Store) DeleteOtherSessions(ctx context.Context, userID int64, keepTokenHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sys_session WHERE user_id=? AND token_hash<>?`, userID, keepTokenHash)
	return err
}

// DeleteUserSessions 删除该账号的全部会话（管理员重置密码 / 二次验证时使用）。
func (s *Store) DeleteUserSessions(ctx context.Context, userID int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sys_session WHERE user_id=?`, userID)
	return err
}

// ---------------------------------------------------------------- 应急安全码

// SetSecurityCode 写入新的安全码哈希。
//
// 会先清空旧记录——一是保证「同时只有一枚有效安全码」，二是让「应急登录用掉旧码」
// 与「管理员重新生成」这两件事共用同一条路径，不会出现两枚码同时有效的窗口。
func (s *Store) SetSecurityCode(ctx context.Context, codeHash string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM sys_security_code`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO sys_security_code(code_hash,created_at) VALUES(?,?)`,
		codeHash, ts(time.Now())); err != nil {
		return err
	}
	return tx.Commit()
}

// GetSecurityCode 返回当前安全码的哈希；未设置时返回 ErrNotFound。
func (s *Store) GetSecurityCode(ctx context.Context) (string, error) {
	var h string
	err := s.db.QueryRowContext(ctx, `SELECT code_hash FROM sys_security_code ORDER BY id DESC LIMIT 1`).Scan(&h)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return h, err
}

// ClearSecurityCode 清空安全码（没有任何有效安全码时，应急登录不可用）。
func (s *Store) ClearSecurityCode(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sys_security_code`)
	return err
}

// ---------------------------------------------------------------- 审计

// AddAudit 追加一条审计记录，并串接哈希链。
func (s *Store) AddAudit(ctx context.Context, e *model.AuditEntry) error {
	if e.Ts.IsZero() {
		e.Ts = time.Now()
	}
	if e.Result == "" {
		e.Result = "ok"
	}
	var prev string
	_ = s.db.QueryRowContext(ctx, `SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1`).Scan(&prev)
	e.PrevHash = prev
	e.Hash = auditHash(e)
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO audit_log(ts,user_id,username,src_ip,action,target_type,target_id,before,after,result,message,prev_hash,hash)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		ts(e.Ts), e.UserID, e.Username, e.SrcIP, e.Action, e.TargetType, e.TargetID,
		e.Before, e.After, e.Result, e.Message, e.PrevHash, e.Hash)
	if err != nil {
		return err
	}
	e.ID, _ = res.LastInsertId()
	return nil
}

func auditHash(e *model.AuditEntry) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%d|%s|%s|%s|%s|%s|%s|%s|%s|%s",
		e.Ts.UTC().Format(tsLayout), e.UserID, e.SrcIP, e.Action, e.TargetType, e.TargetID,
		e.Before, e.After, e.Result, e.Message, e.PrevHash)
	return hex.EncodeToString(h.Sum(nil))
}

// ListAudit 分页查询审计记录。
func (s *Store) ListAudit(ctx context.Context, f model.AuditFilter) ([]model.AuditEntry, int64, error) {
	where := []string{"1=1"}
	args := []any{}
	if f.Username != "" {
		where = append(where, "username LIKE ?")
		args = append(args, "%"+f.Username+"%")
	}
	if f.Action != "" {
		where = append(where, "action LIKE ?")
		args = append(args, f.Action+"%")
	}
	if f.TargetType != "" {
		where = append(where, "target_type=?")
		args = append(args, f.TargetType)
	}
	if f.From != nil {
		where = append(where, "ts>=?")
		args = append(args, ts(*f.From))
	}
	if f.To != nil {
		where = append(where, "ts<=?")
		args = append(args, ts(*f.To))
	}
	cond := strings.Join(where, " AND ")
	var total int64
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM audit_log WHERE `+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	q := `SELECT id,ts,user_id,username,src_ip,action,target_type,target_id,before,after,result,message,prev_hash,hash
	      FROM audit_log WHERE ` + cond + ` ORDER BY id DESC LIMIT ? OFFSET ?`
	qargs := append(append([]any{}, args...), limit, f.Offset)
	rows, err := s.db.QueryContext(ctx, q, qargs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []model.AuditEntry{}
	for rows.Next() {
		var e model.AuditEntry
		var t string
		if err := rows.Scan(&e.ID, &t, &e.UserID, &e.Username, &e.SrcIP, &e.Action, &e.TargetType, &e.TargetID,
			&e.Before, &e.After, &e.Result, &e.Message, &e.PrevHash, &e.Hash); err != nil {
			return nil, 0, err
		}
		e.Ts = parseTS(t)
		out = append(out, e)
	}
	return out, total, rows.Err()
}

// VerifyAudit 校验审计链完整性，返回首个异常记录 ID（0 表示完整）。
func (s *Store) VerifyAudit(ctx context.Context) (bool, int64, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,ts,user_id,username,src_ip,action,target_type,target_id,before,after,result,message,prev_hash,hash
		 FROM audit_log ORDER BY id`)
	if err != nil {
		return false, 0, err
	}
	defer rows.Close()
	prev := ""
	for rows.Next() {
		var e model.AuditEntry
		var t string
		if err := rows.Scan(&e.ID, &t, &e.UserID, &e.Username, &e.SrcIP, &e.Action, &e.TargetType, &e.TargetID,
			&e.Before, &e.After, &e.Result, &e.Message, &e.PrevHash, &e.Hash); err != nil {
			return false, 0, err
		}
		e.Ts = parseTS(t)
		if e.PrevHash != prev {
			return false, e.ID, nil
		}
		if auditHash(&e) != e.Hash {
			return false, e.ID, nil
		}
		prev = e.Hash
	}
	return true, 0, rows.Err()
}

// ---------------------------------------------------------------- 应用日志

// AddLog 追加应用日志。
func (s *Store) AddLog(ctx context.Context, level, scope, message, fields string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO app_log(ts,level,scope,message,fields) VALUES(?,?,?,?,?)`,
		ts(time.Now()), level, scope, message, fields)
	return err
}

// ListLogs 查询应用日志。
func (s *Store) ListLogs(ctx context.Context, level, scope, keyword string, limit, offset int) ([]model.LogEntry, int64, error) {
	where := []string{"1=1"}
	args := []any{}
	if level != "" {
		where = append(where, "level=?")
		args = append(args, level)
	}
	if scope != "" {
		where = append(where, "scope=?")
		args = append(args, scope)
	}
	if keyword != "" {
		where = append(where, "message LIKE ?")
		args = append(args, "%"+keyword+"%")
	}
	cond := strings.Join(where, " AND ")
	var total int64
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM app_log WHERE `+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,ts,level,scope,message,fields FROM app_log WHERE `+cond+` ORDER BY id DESC LIMIT ? OFFSET ?`,
		append(append([]any{}, args...), limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []model.LogEntry{}
	for rows.Next() {
		var e model.LogEntry
		var t string
		if err := rows.Scan(&e.ID, &t, &e.Level, &e.Scope, &e.Message, &e.Fields); err != nil {
			return nil, 0, err
		}
		e.Ts = parseTS(t)
		out = append(out, e)
	}
	return out, total, rows.Err()
}

// PruneLogs 清理旧日志。
func (s *Store) PruneLogs(ctx context.Context, before time.Time) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM app_log WHERE ts < ?`, ts(before))
	return err
}

// ---------------------------------------------------------------- 设置

// GetSetting 读取配置项，不存在时返回默认值。
func (s *Store) GetSetting(ctx context.Context, key, def string) string {
	var v string
	if err := s.db.QueryRowContext(ctx, `SELECT value FROM app_setting WHERE key=?`, key).Scan(&v); err != nil {
		return def
	}
	return v
}

// LookupSetting 读取配置项，并区分「没配置过」与「配置成了空值」。
//
// 少数设置项需要这个区分才能正确迁移：例如事件通知的开关集合，
// 「一个都没关」与「这一项在旧版本里还不存在」都表现为空串，
// 但两者的处理方式不同（前者要保持、后者要补默认值）。
func (s *Store) LookupSetting(ctx context.Context, key string) (string, bool) {
	var v string
	if err := s.db.QueryRowContext(ctx, `SELECT value FROM app_setting WHERE key=?`, key).Scan(&v); err != nil {
		return "", false
	}
	return v, true
}

// SetSetting 写入配置项。
func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO app_setting(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

// AllSettings 返回全部配置项。
func (s *Store) AllSettings(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key,value FROM app_setting`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------- 备份记录

// 备份记录类型。快照与备份同表存放，靠该字段分流：
// 备份列表只显示 manual/imported，快照列表只显示 auto。
const (
	BackupKindManual   = "manual"   // 用户主动创建的全量备份
	BackupKindImported = "imported" // 用户从外部导入的备份文件
	BackupKindAuto     = "auto"     // 关键配置操作前自动留下的配置快照
)

type BackupRecord struct {
	ID         int64     `json:"id"`
	Filename   string    `json:"filename"`
	Size       int64     `json:"size"`
	SHA256     string    `json:"sha256"`
	Kind       string    `json:"kind"`
	Note       string    `json:"note"`
	IncludeKey bool      `json:"include_key"`
	CreatedAt  time.Time `json:"created_at"`
}

// CreateBackupRecord 记录一次备份。
func (s *Store) CreateBackupRecord(ctx context.Context, r *BackupRecord) error {
	now := time.Now()
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO backup_record(filename,size,sha256,kind,note,include_key,created_at) VALUES(?,?,?,?,?,?,?)`,
		r.Filename, r.Size, r.SHA256, r.Kind, r.Note, b2i(r.IncludeKey), ts(now))
	if err != nil {
		return err
	}
	r.ID, _ = res.LastInsertId()
	r.CreatedAt = now
	return nil
}

// ListBackups 返回备份记录（含自动快照，调用方按 kind 自行区分）。
func (s *Store) ListBackups(ctx context.Context) ([]BackupRecord, error) {
	return s.ListBackupsByKind(ctx)
}

// ListBackupsByKind 按类型返回备份记录，结果按时间倒序。
//
// 快照（kind=auto）与用户备份共用 backup_record 表：前者只含配置、可随时回滚，
// 后者是用户主动存档的全量备份。列表接口靠 kind 分流，
// 否则每次改一条设备都会冒出一行快照，把真正的备份挤得看不见。
// 不传 kinds 表示不限类型。
func (s *Store) ListBackupsByKind(ctx context.Context, kinds ...string) ([]BackupRecord, error) {
	query := `SELECT id,filename,size,sha256,kind,note,include_key,created_at FROM backup_record`
	args := make([]any, 0, len(kinds))
	if len(kinds) > 0 {
		holders := make([]string, 0, len(kinds))
		for _, k := range kinds {
			holders = append(holders, "?")
			args = append(args, k)
		}
		query += ` WHERE kind IN (` + strings.Join(holders, ",") + `)`
	}
	query += ` ORDER BY id DESC`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []BackupRecord{}
	for rows.Next() {
		var r BackupRecord
		var t string
		var ik int
		if err := rows.Scan(&r.ID, &r.Filename, &r.Size, &r.SHA256, &r.Kind, &r.Note, &ik, &t); err != nil {
			return nil, err
		}
		r.IncludeKey = ik == 1
		r.CreatedAt = parseTS(t)
		out = append(out, r)
	}
	return out, rows.Err()
}

// DeleteBackupRecord 删除备份记录。
func (s *Store) DeleteBackupRecord(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM backup_record WHERE id=?`, id)
	return err
}

// GetUserByTrimUID 按飞牛用户 UID 查账号 —— 免密登录的对应关系就靠它。
func (s *Store) GetUserByTrimUID(ctx context.Context, uid int64) (*model.User, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id,username,password_hash,totp_secret,role,status,last_login_at,created_at,COALESCE(trim_uid,0),COALESCE(trim_name,'') FROM sys_user WHERE trim_uid=?`, uid)
	u, err := s.scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return u, err
}

// CreateGatewayUser 为飞牛用户建一个本应用账号。
//
// passwordPlaceholder 由调用方给一个**格式非法**的值：VerifyPassword 解析失败即返回 false，
// 于是这类账号永远不可能用密码登录 —— 这不靠额外判断，是校验逻辑自带的性质。
func (s *Store) CreateGatewayUser(ctx context.Context, uid int64, username, name, passwordPlaceholder, role string) (*model.User, error) {
	now := time.Now()
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO sys_user(username,password_hash,totp_secret,role,status,created_at,trim_uid,trim_name) VALUES(?,?,'',?,1,?,?,?)`,
		username, passwordPlaceholder, role, ts(now), uid, name)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &model.User{
		ID: id, Username: username, PasswordHash: passwordPlaceholder,
		Role: role, Status: 1, CreatedAt: now, TrimUID: uid, TrimName: name,
	}, nil
}

// FreeUsername 找一个没被占用的账号名：先用首选名，被占用时依次加后缀。
//
// 为什么需要它：飞牛账号的账号名优先用「飞牛用户名」，而这个名字完全可能与已有账号重名
// （尤其是一个叫 admin 的飞牛普通用户，与本地管理员同名）。此时唯一安全的做法是**另起一个名字** ——
// 复用别人的账号等于把别人的权限交给这个飞牛用户。
func (s *Store) FreeUsername(ctx context.Context, want, suffix string) (string, error) {
	for i := 0; i < 50; i++ {
		candidate := want
		if i == 1 {
			candidate = want + "-" + suffix
		} else if i > 1 {
			candidate = fmt.Sprintf("%s-%s-%d", want, suffix, i)
		}
		var n int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM sys_user WHERE username=?`, candidate).Scan(&n); err != nil {
			return "", err
		}
		if n == 0 {
			return candidate, nil
		}
	}
	return "", errors.New("无法为飞牛账号生成可用的账号名")
}
