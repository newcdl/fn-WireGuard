// Package store 是 SQLite 数据访问层，fnwg-web 与 fnwg-agent 共享同一数据库（WAL 模式）。
package store

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"fnwg/internal/model"
	"fnwg/internal/secretbox"

	_ "modernc.org/sqlite"
)

// Store 封装数据库连接与加密盒。
type Store struct {
	db  *sql.DB
	box *secretbox.Box
}

// Open 打开（必要时创建）数据库并执行 schema 迁移。
func Open(path string, box *secretbox.Box) (*Store, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(1)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// SQLite 单写者模型，限制连接数避免 SQLITE_BUSY。
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(time.Hour)

	s := &Store{db: db, box: box}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close 关闭数据库。
func (s *Store) Close() error { return s.db.Close() }

// DB 暴露底层连接，供特殊查询使用。
func (s *Store) DB() *sql.DB { return s.db }

const schema = `
CREATE TABLE IF NOT EXISTS wg_interface (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  name        TEXT    NOT NULL UNIQUE,
  uuid        TEXT    NOT NULL,
  private_key BLOB,
  listen_port INTEGER NOT NULL DEFAULT 51820,
  fwmark      INTEGER NOT NULL DEFAULT 0,
  mtu         INTEGER NOT NULL DEFAULT 1420,
  addresses   TEXT    NOT NULL DEFAULT '[]',
  dns         TEXT    NOT NULL DEFAULT '[]',
  dns_mode    TEXT    NOT NULL DEFAULT 'client',
  route_table TEXT    NOT NULL DEFAULT 'auto',
  pre_up      TEXT    NOT NULL DEFAULT '',
  post_up     TEXT    NOT NULL DEFAULT '',
  pre_down    TEXT    NOT NULL DEFAULT '',
  post_down   TEXT    NOT NULL DEFAULT '',
  enabled     INTEGER NOT NULL DEFAULT 1,
  autostart   INTEGER NOT NULL DEFAULT 1,
  allow_lan   INTEGER NOT NULL DEFAULT 0,
  revision    INTEGER NOT NULL DEFAULT 1,
  created_at  TEXT    NOT NULL,
  updated_at  TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS wg_peer (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  interface_id  INTEGER NOT NULL REFERENCES wg_interface(id) ON DELETE CASCADE,
  name          TEXT    NOT NULL DEFAULT '',
  public_key    TEXT    NOT NULL,
  preshared_key BLOB,
  client_priv   BLOB,
  route_mode    TEXT    NOT NULL DEFAULT 'lan',
  client_ips    TEXT    NOT NULL DEFAULT '[]',
  endpoint_host TEXT    NOT NULL DEFAULT '',
  endpoint_port INTEGER NOT NULL DEFAULT 0,
  allowed_ips   TEXT    NOT NULL DEFAULT '[]',
  keepalive     INTEGER NOT NULL DEFAULT 0,
  group_tag     TEXT    NOT NULL DEFAULT '',
  remark        TEXT    NOT NULL DEFAULT '',
  quota_rx      INTEGER NOT NULL DEFAULT 0,
  quota_tx      INTEGER NOT NULL DEFAULT 0,
  expire_at     TEXT,
  enabled       INTEGER NOT NULL DEFAULT 1,
  created_at    TEXT    NOT NULL,
  updated_at    TEXT    NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_peer_iface_pub ON wg_peer(interface_id, public_key);
CREATE INDEX IF NOT EXISTS idx_peer_iface ON wg_peer(interface_id);

CREATE TABLE IF NOT EXISTS wg_peer_stat (
  interface_id INTEGER NOT NULL,
  public_key   TEXT    NOT NULL,
  ts           INTEGER NOT NULL,
  rx_bytes     INTEGER NOT NULL DEFAULT 0,
  tx_bytes     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_stat_peer_ts ON wg_peer_stat(interface_id, public_key, ts);

CREATE TABLE IF NOT EXISTS sys_user (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  username      TEXT    NOT NULL UNIQUE,
  password_hash TEXT    NOT NULL,
  totp_secret   TEXT    NOT NULL DEFAULT '',
  role          TEXT    NOT NULL DEFAULT 'viewer',
  status        INTEGER NOT NULL DEFAULT 1,
  last_login_at TEXT,
  created_at    TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS sys_session (
  token_hash TEXT    PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES sys_user(id) ON DELETE CASCADE,
  expires_at TEXT    NOT NULL,
  created_at TEXT    NOT NULL,
  user_agent TEXT    NOT NULL DEFAULT '',
  src_ip     TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_session_user ON sys_session(user_id);

CREATE TABLE IF NOT EXISTS audit_log (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  ts          TEXT    NOT NULL,
  user_id     INTEGER NOT NULL DEFAULT 0,
  username    TEXT    NOT NULL DEFAULT '',
  src_ip      TEXT    NOT NULL DEFAULT '',
  action      TEXT    NOT NULL,
  target_type TEXT    NOT NULL DEFAULT '',
  target_id   TEXT    NOT NULL DEFAULT '',
  before      TEXT    NOT NULL DEFAULT '',
  after       TEXT    NOT NULL DEFAULT '',
  result      TEXT    NOT NULL DEFAULT 'ok',
  message     TEXT    NOT NULL DEFAULT '',
  prev_hash   TEXT    NOT NULL DEFAULT '',
  hash        TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts DESC);

CREATE TABLE IF NOT EXISTS app_log (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  ts      TEXT    NOT NULL,
  level   TEXT    NOT NULL DEFAULT 'info',
  scope   TEXT    NOT NULL DEFAULT '',
  message TEXT    NOT NULL,
  fields  TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_applog_ts ON app_log(ts DESC);

CREATE TABLE IF NOT EXISTS app_setting (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS backup_record (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  filename   TEXT    NOT NULL,
  size       INTEGER NOT NULL DEFAULT 0,
  sha256     TEXT    NOT NULL DEFAULT '',
  kind       TEXT    NOT NULL DEFAULT 'manual',
  note       TEXT    NOT NULL DEFAULT '',
  include_key INTEGER NOT NULL DEFAULT 0,
  created_at TEXT    NOT NULL
);
`

func (s *Store) migrate() error {
	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("初始化数据库失败: %w", err)
	}
	// 旧版本数据库补列
	for _, c := range []struct{ table, column, ddl string }{
		{"wg_peer", "route_mode", `ALTER TABLE wg_peer ADD COLUMN route_mode TEXT NOT NULL DEFAULT 'lan'`},
		{"wg_peer", "client_ips", `ALTER TABLE wg_peer ADD COLUMN client_ips TEXT NOT NULL DEFAULT '[]'`},
		// 内网访问开关：历史数据默认关闭，避免升级即改用户的网络；
		// 新建连接时由服务层默认开启。
		{"wg_interface", "allow_lan", `ALTER TABLE wg_interface ADD COLUMN allow_lan INTEGER NOT NULL DEFAULT 0`},
	} {
		if err := s.ensureColumn(c.table, c.column, c.ddl); err != nil {
			return err
		}
	}
	return s.migrateNetworkSafety()
}

func (s *Store) ensureColumn(table, column, ddl string) error {
	rows, err := s.db.Query(fmt.Sprintf(`PRAGMA table_info(%s)`, table))
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			cid     int
			name    string
			ctype   string
			notNull int
			dflt    sql.NullString
			pk      int
		)
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &dflt, &pk); err != nil {
			return err
		}
		if name == column {
			return nil
		}
	}
	if _, err := s.db.Exec(ddl); err != nil {
		return fmt.Errorf("为 %s 补列 %s 失败: %w", table, column, err)
	}
	return nil
}

// migrateNetworkSafety 修正历史版本中可能危及 NAS 自身网络的数据。
//
// 背景：0.2.0 及更早版本把「服务端准入地址」与「客户端上网方式」混为一个字段，
// 当用户在设备上填写 0.0.0.0/0 时，会在 NAS 上写入默认路由，抢占系统默认路由，
// 导致 FN Connect 等系统功能断网。这里把这类数据转换成安全表示：
//  1. 设备 AllowedIPs 中的 0.0.0.0/0、::/0 移除，并把上网方式设为 full（只影响客户端配置）；
//  2. 接口的路由管理方式由旧的 auto 统一降级为 off（不再改动系统路由）。
func (s *Store) migrateNetworkSafety() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// 1) 接口：auto / 数字 → off
	if _, err := tx.Exec(`UPDATE wg_interface SET route_table=? WHERE route_table NOT IN (?, ?)`,
		model.RouteTableOff, model.RouteTableOff, model.RouteTableClient); err != nil {
		return err
	}

	// 2) 设备：拆分危险的全网段写法
	rows, err := tx.Query(`SELECT id, IFNULL(allowed_ips,'[]'), IFNULL(route_mode,'lan') FROM wg_peer`)
	if err != nil {
		return err
	}
	type fix struct {
		id      int64
		allowed string
		mode    string
	}
	var fixes []fix
	for rows.Next() {
		var id int64
		var allowed, mode string
		if err := rows.Scan(&id, &allowed, &mode); err != nil {
			rows.Close()
			return err
		}
		list := jsonStrings(allowed)
		kept := make([]string, 0, len(list))
		dangerous := false
		for _, cidr := range list {
			if isDefaultRouteCIDR(cidr) {
				dangerous = true
				continue
			}
			kept = append(kept, cidr)
		}
		if !dangerous {
			continue
		}
		if mode == "" || mode == model.RouteModeLAN {
			mode = model.RouteModeFull // 原来是"全部流量"，转换到客户端侧的语义
		}
		fixes = append(fixes, fix{id: id, allowed: mustJSON(kept), mode: mode})
	}
	rows.Close()
	for _, f := range fixes {
		if _, err := tx.Exec(`UPDATE wg_peer SET allowed_ips=?, route_mode=? WHERE id=?`, f.allowed, f.mode, f.id); err != nil {
			return err
		}
	}
	if len(fixes) > 0 {
		_, _ = tx.Exec(`INSERT INTO app_log(ts,level,scope,message,fields) VALUES(?,?,?,?,?)`,
			ts(time.Now()), "warn", "migrate",
			"检测到会修改 NAS 系统路由的历史配置，已自动转换为安全形式（设备上网方式）",
			fmt.Sprintf("已修正 %d 台设备", len(fixes)))
	}
	return tx.Commit()
}

// isDefaultRouteCIDR 判断是否为默认路由网段。
func isDefaultRouteCIDR(cidr string) bool {
	switch strings.TrimSpace(cidr) {
	case "0.0.0.0/0", "::/0", "0/0", "0::/0":
		return true
	}
	return false
}

const tsLayout = time.RFC3339Nano

func ts(t time.Time) string { return t.UTC().Format(tsLayout) }

func parseTS(v string) time.Time {
	t, err := time.Parse(tsLayout, v)
	if err != nil {
		return time.Time{}
	}
	return t
}

func parseTSNull(v sql.NullString) *time.Time {
	if !v.Valid || v.String == "" {
		return nil
	}
	t := parseTS(v.String)
	return &t
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
