package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// DNSRecord 是一条内网域名记录（主机名 → 家里设备地址）。
type DNSRecord struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	IP        string    `json:"ip"`
	Note      string    `json:"note"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// NormalizeDNSName 归一化主机名：去空白、去末尾的点、转小写。
//
// 统一归一化是必须的：DNS 大小写不敏感，而 SQLite 的 UNIQUE 区分大小写，
// 不归一化就会出现「NAS」与「nas」两条记录，客户端查哪个都不稳定。
func NormalizeDNSName(v string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(v), "."))
}

// ListDNSRecords 返回全部内网域名记录。
func (s *Store) ListDNSRecords(ctx context.Context) ([]DNSRecord, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,name,ip,note,created_at,updated_at FROM dns_record ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DNSRecord{}
	for rows.Next() {
		var r DNSRecord
		var created, updated string
		if err := rows.Scan(&r.ID, &r.Name, &r.IP, &r.Note, &created, &updated); err != nil {
			return nil, err
		}
		r.CreatedAt = parseTS(created)
		r.UpdatedAt = parseTS(updated)
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetDNSRecord 按主键查询。
func (s *Store) GetDNSRecord(ctx context.Context, id int64) (*DNSRecord, error) {
	var r DNSRecord
	var created, updated string
	err := s.db.QueryRowContext(ctx,
		`SELECT id,name,ip,note,created_at,updated_at FROM dns_record WHERE id=?`, id).
		Scan(&r.ID, &r.Name, &r.IP, &r.Note, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	r.CreatedAt = parseTS(created)
	r.UpdatedAt = parseTS(updated)
	return &r, nil
}

// CreateDNSRecord 新增记录。
func (s *Store) CreateDNSRecord(ctx context.Context, r *DNSRecord) error {
	r.Name = NormalizeDNSName(r.Name)
	now := time.Now()
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO dns_record(name,ip,note,created_at,updated_at) VALUES(?,?,?,?,?)`,
		r.Name, r.IP, r.Note, ts(now), ts(now))
	if err != nil {
		return err
	}
	r.ID, _ = res.LastInsertId()
	r.CreatedAt, r.UpdatedAt = now, now
	return nil
}

// UpdateDNSRecord 更新记录。
func (s *Store) UpdateDNSRecord(ctx context.Context, r *DNSRecord) error {
	r.Name = NormalizeDNSName(r.Name)
	now := time.Now()
	res, err := s.db.ExecContext(ctx,
		`UPDATE dns_record SET name=?,ip=?,note=?,updated_at=? WHERE id=?`,
		r.Name, r.IP, r.Note, ts(now), r.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	r.UpdatedAt = now
	return nil
}

// DeleteDNSRecord 删除记录。
func (s *Store) DeleteDNSRecord(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM dns_record WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
