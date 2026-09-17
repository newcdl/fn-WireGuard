package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// GatewayIdentity 是「飞牛统一网关账号 ↔ 本地账号」的一条映射。
//
// 网关只负责「已登录」，本应用仍要自己负责「有什么权限」：映射到本地账号后，
// 后续请求一律走本地会话与本地角色，网关头不再参与任何业务判断。
type GatewayIdentity struct {
	TrimUID      string
	UserID       int64
	TrimUsername string
	IsAdmin      bool
	LastSeenAt   time.Time
	CreatedAt    time.Time
}

// GetGatewayIdentity 按飞牛 UID 查询映射；不存在时返回 ErrNotFound。
func (s *Store) GetGatewayIdentity(ctx context.Context, trimUID string) (*GatewayIdentity, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT trim_uid,user_id,trim_username,is_admin,last_seen_at,created_at
		   FROM sys_gateway_identity WHERE trim_uid=?`, trimUID)
	g, err := scanGatewayIdentity(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return g, err
}

// GetGatewayIdentityByUser 按本地账号反查映射（用于界面标注账号来源）。
func (s *Store) GetGatewayIdentityByUser(ctx context.Context, userID int64) (*GatewayIdentity, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT trim_uid,user_id,trim_username,is_admin,last_seen_at,created_at
		   FROM sys_gateway_identity WHERE user_id=?`, userID)
	g, err := scanGatewayIdentity(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return g, err
}

// CreateGatewayIdentity 写入一条映射。
func (s *Store) CreateGatewayIdentity(ctx context.Context, g *GatewayIdentity) error {
	now := time.Now()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sys_gateway_identity(trim_uid,user_id,trim_username,is_admin,last_seen_at,created_at)
		 VALUES(?,?,?,?,?,?)`,
		g.TrimUID, g.UserID, g.TrimUsername, boolInt(g.IsAdmin), ts(now), ts(now))
	if err != nil {
		return err
	}
	g.CreatedAt, g.LastSeenAt = now, now
	return nil
}

// UpdateGatewayIdentity 刷新用户名、管理员标记与最近登录时间。
//
// 每次网关登录都刷新：飞牛那边把某人加/撤管理员后，本应用的角色必须跟着变，
// 否则「在 NAS 里已撤销管理员」的人会一直留着本地管理员权限。
func (s *Store) UpdateGatewayIdentity(ctx context.Context, g *GatewayIdentity) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE sys_gateway_identity SET trim_username=?,is_admin=?,last_seen_at=? WHERE trim_uid=?`,
		g.TrimUsername, boolInt(g.IsAdmin), ts(time.Now()), g.TrimUID)
	return err
}

// ListGatewayIdentities 返回全部映射。
func (s *Store) ListGatewayIdentities(ctx context.Context) ([]GatewayIdentity, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT trim_uid,user_id,trim_username,is_admin,last_seen_at,created_at
		   FROM sys_gateway_identity ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []GatewayIdentity{}
	for rows.Next() {
		g, err := scanGatewayIdentity(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *g)
	}
	return out, rows.Err()
}

func scanGatewayIdentity(sc interface{ Scan(...any) error }) (*GatewayIdentity, error) {
	var (
		g         GatewayIdentity
		isAdmin   int
		lastSeen  sql.NullString
		createdAt string
	)
	if err := sc.Scan(&g.TrimUID, &g.UserID, &g.TrimUsername, &isAdmin, &lastSeen, &createdAt); err != nil {
		return nil, err
	}
	g.IsAdmin = isAdmin == 1
	if t := parseTSNull(lastSeen); t != nil {
		g.LastSeenAt = *t
	}
	g.CreatedAt = parseTS(createdAt)
	return &g, nil
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
