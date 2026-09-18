// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

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
  isolate_peers INTEGER NOT NULL DEFAULT 0,
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
  -- config_fp 是设备上次拿到配置时的客户端配置指纹（不含密钥），
  -- 用来判断「设备里那份配置是不是已经过期」，空表示从未生成过配置。
  config_fp     TEXT    NOT NULL DEFAULT '',
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

-- 按小时聚合的流量：报表与「每月额度」的唯一依据。
--
-- 为什么不直接用上面那张原始采样表算：
--   原始采样是「一个点一行」，按 5 分钟采样 × 每台设备 × 90 天就是百万级行数，
--   长期写放大不可接受（ROADMAP R8）；这里每小时一行、增量累加，
--   20 台设备保留 90 天也只有四万余行。
--
-- 为什么存增量而不是累计快照：
--   内核的累计计数会在接口重建（重启、重新下发配置）后归零，
--   存增量才能让「这个月用了多少」不受影响 —— 采集侧负责识别计数回绕、
--   把它当作新基线，绝不把负数写进来。
CREATE TABLE IF NOT EXISTS wg_traffic_hourly (
  peer_id      INTEGER NOT NULL,
  interface_id INTEGER NOT NULL,
  hour_ts      INTEGER NOT NULL,
  rx_bytes     INTEGER NOT NULL DEFAULT 0,
  tx_bytes     INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_traffic_hour ON wg_traffic_hourly(peer_id, hour_ts);
CREATE INDEX IF NOT EXISTS idx_traffic_iface ON wg_traffic_hourly(interface_id, hour_ts);

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

-- 二次验证（TOTP）的登录挑战：口令校验通过后、动态口令校验通过前，会话尚未建立。
-- 单独一张表而不是复用 sys_session 加个 pending 标记，是为了从结构上杜绝
-- 「未通过二次验证的令牌被当成已登录会话」——那种写法一旦漏判一处就是越权。
CREATE TABLE IF NOT EXISTS sys_totp_challenge (
  token_hash TEXT    PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES sys_user(id) ON DELETE CASCADE,
  expires_at TEXT    NOT NULL,
  attempts   INTEGER NOT NULL DEFAULT 0,
  created_at TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_totp_challenge_user ON sys_totp_challenge(user_id);

-- 二次验证的恢复码：只存 argon2id 哈希（与登录口令同一套算法，参数也一致），
-- 明文仅在开启时展示一次、之后无法再取回。used_at 非空表示已用过（一次性）。
CREATE TABLE IF NOT EXISTS sys_recovery_code (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER NOT NULL REFERENCES sys_user(id) ON DELETE CASCADE,
  code_hash  TEXT    NOT NULL,
  used_at    TEXT,
  created_at TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_recovery_user ON sys_recovery_code(user_id);

-- 受信任设备：勾选「信任本设备」后下发的设备令牌（只存 SHA-256，明文仅签发时返回一次）。
-- 命中且未过期即可跳过二次验证，这正是飞牛官方 2FA 的「信任本设备」语义。
-- 注意：它的本质是「用设备上的凭据替代第二个因子」，所以改密码、关闭/重开二次验证、
-- 管理员重置时都必须立即清空——否则它就成了一条绕过 2FA 的永久后门。
CREATE TABLE IF NOT EXISTS sys_trusted_device (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id      INTEGER NOT NULL REFERENCES sys_user(id) ON DELETE CASCADE,
  token_hash   TEXT    NOT NULL UNIQUE,
  name         TEXT    NOT NULL DEFAULT '',
  src_ip       TEXT    NOT NULL DEFAULT '',
  created_at   TEXT    NOT NULL,
  last_used_at TEXT    NOT NULL,
  expires_at   TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_trusted_user ON sys_trusted_device(user_id);

-- 应急「安全码」：所有常规登录途径都失效时（飞牛网关异常、管理员忘密码、2FA 手机丢失）
-- 的最后一道入口。它不属于任何账号，是实例级凭据，因此单独成表而不放进 app_setting
-- —— 放进设置表会被全量备份带走，等于把万能钥匙抄进备份文件里。
-- 只存 argon2id 哈希，明文仅在生成时展示一次；用一次即作废。
CREATE TABLE IF NOT EXISTS sys_security_code (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  code_hash  TEXT    NOT NULL,
  created_at TEXT    NOT NULL
);

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

-- 内网域名解析：用户维护的「主机名 → 家里设备地址」对照表。
-- name 统一以小写去重（DNS 大小写不敏感），ip 目前只支持 IPv4。
CREATE TABLE IF NOT EXISTS dns_record (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  name       TEXT    NOT NULL,
  ip         TEXT    NOT NULL,
  note       TEXT    NOT NULL DEFAULT '',
  created_at TEXT    NOT NULL,
  updated_at TEXT    NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_dns_name ON dns_record(name);
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
		// 设备间隔离：默认关闭。历史连接升级后行为必须与升级前完全一致，
		// 这项是「新增限制」，绝不能默认打开（那会突然切断用户已有的设备互访）。
		{"wg_interface", "isolate_peers", `ALTER TABLE wg_interface ADD COLUMN isolate_peers INTEGER NOT NULL DEFAULT 0`},
		// 客户端配置指纹：默认空表示「从未生成过配置」，
		// 此时不显示「配置已过期」——升级不该让所有设备列表突然飘满提示。
		{"wg_peer", "config_fp", `ALTER TABLE wg_peer ADD COLUMN config_fp TEXT NOT NULL DEFAULT ''`},
	} {
		if err := s.ensureColumn(c.table, c.column, c.ddl); err != nil {
			return err
		}
	}
	if err := s.migrateNetworkSafety(); err != nil {
		return err
	}
	return nil
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
