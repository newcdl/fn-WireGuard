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
	if err := sc.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.TOTPSecret, &u.Role, &u.Status, &lastLoginAt, &createdAt); err != nil {
		return nil, err
	}
	u.LastLoginAt = parseTSNull(lastLoginAt)
	u.CreatedAt = parseTS(createdAt)
	return &u, nil
}

// ListUsers 返回全部账号。
func (s *Store) ListUsers(ctx context.Context) ([]model.User, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,username,password_hash,totp_secret,role,status,last_login_at,created_at FROM sys_user ORDER BY id`)
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
		`SELECT id,username,password_hash,totp_secret,role,status,last_login_at,created_at FROM sys_user WHERE username=?`, username)
	u, err := s.scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return u, err
}

// GetUser 按主键查询。
func (s *Store) GetUser(ctx context.Context, id int64) (*model.User, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id,username,password_hash,totp_secret,role,status,last_login_at,created_at FROM sys_user WHERE id=?`, id)
	u, err := s.scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return u, err
}

// UpdateUser 更新账号基本信息。
func (s *Store) UpdateUser(ctx context.Context, u *model.User) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE sys_user SET password_hash=?,totp_secret=?,role=?,status=? WHERE id=?`,
		u.PasswordHash, u.TOTPSecret, u.Role, u.Status, u.ID)
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

// ListBackups 返回备份记录。
func (s *Store) ListBackups(ctx context.Context) ([]BackupRecord, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,filename,size,sha256,kind,note,include_key,created_at FROM backup_record ORDER BY id DESC`)
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
