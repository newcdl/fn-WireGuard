package store_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"fnwg/internal/model"
	"fnwg/internal/secretbox"
	"fnwg/internal/store"
)

// TestAllowLANColumnAddedByMigration 回归「升级不会读不出数据」：
// 旧版本的 wg_interface 表没有 allow_lan 列，升级后必须被自动补上，
// 且历史连接默认为**关闭**（避免升级即改用户的网络）。
// 如果这一步失败，用户升级后整个界面会读不出连接。
func TestAllowLANColumnAddedByMigration(t *testing.T) {
	dir := t.TempDir()
	box, err := secretbox.New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(dir, "old.db")

	// 用旧版表结构建库：wg_interface 里没有 allow_lan
	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`CREATE TABLE wg_interface (
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
		revision    INTEGER NOT NULL DEFAULT 1,
		created_at  TEXT    NOT NULL,
		updated_at  TEXT    NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(
		`INSERT INTO wg_interface(name,uuid,private_key,addresses,dns,route_table,enabled,autostart,revision,created_at,updated_at)
		 VALUES('wg0','old-uuid',x'',?,?,'off',1,1,1,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`,
		`["10.10.0.1/24"]`, `[]`); err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	// 用新版本打开 → 触发补列迁移
	st, err := store.Open(dbPath, box)
	if err != nil {
		t.Fatalf("打开旧库失败（说明迁移没把 allow_lan 列补上）: %v", err)
	}
	defer st.Close()

	it, err := st.GetInterface(context.Background(), 1)
	if err != nil {
		t.Fatalf("读取旧连接失败: %v", err)
	}
	if it.AllowLAN {
		t.Fatal("历史连接的内网访问开关必须默认关闭，避免升级即改用户网络")
	}
	if it.Name != "wg0" || it.RouteTable != model.RouteTableOff {
		t.Fatalf("旧数据其余字段应保持原样: %+v", it)
	}
}

// TestNetworkSafetyMigration 是安全回归测试：
// 升级到 0.3.0 后，历史库里"会把 NAS 默认路由抢走"的数据必须被自动转换成安全形式，
// 这样用户即使直接用旧数据重装，也不会再次把系统网络弄坏。
func TestNetworkSafetyMigration(t *testing.T) {
	dir := t.TempDir()
	box, err := secretbox.New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(dir, "migrate.db")

	st, err := store.Open(dbPath, box)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// 模拟 0.2.0 的历史数据：接口用的是旧的 auto 路由模式，设备准入地址含 0.0.0.0/0
	if _, err := st.DB().ExecContext(ctx,
		`INSERT INTO wg_interface(name,uuid,private_key,addresses,dns,route_table,enabled,autostart,revision,created_at,updated_at)
		 VALUES('wg0','old-uuid',x'',?,?,'auto',1,1,1,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`,
		`["10.10.0.1/24"]`, `[]`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().ExecContext(ctx,
		`INSERT INTO wg_peer(interface_id,name,public_key,preshared_key,client_priv,route_mode,client_ips,endpoint_host,
		 endpoint_port,allowed_ips,keepalive,group_tag,remark,quota_rx,quota_tx,enabled,created_at,updated_at)
		 VALUES(1,'旧设备','PUBKEY',NULL,NULL,'lan','[]','',0,?,25,'','',0,0,1,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`,
		`["10.10.0.2/32","0.0.0.0/0","::/0"]`); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	// 重新打开触发迁移
	st2, err := store.Open(dbPath, box)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()

	it, err := st2.GetInterface(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if it.RouteTable != model.RouteTableOff {
		t.Fatalf("旧的 auto 路由模式必须被降级为 off，实际: %s", it.RouteTable)
	}

	p, err := st2.GetPeer(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, cidr := range p.AllowedIPs {
		if cidr == "0.0.0.0/0" || cidr == "::/0" {
			t.Fatalf("危险网段未被清理: %v", p.AllowedIPs)
		}
	}
	if len(p.AllowedIPs) != 1 || p.AllowedIPs[0] != "10.10.0.2/32" {
		t.Fatalf("应保留正常的准入地址，实际: %v", p.AllowedIPs)
	}
	if p.RouteMode != model.RouteModeFull {
		t.Fatalf("原来是全网段通行，应转换为「全部流量走本连接」，实际: %s", p.RouteMode)
	}

	// 迁移应留下可追溯的日志
	logs, total, err := st2.ListLogs(ctx, "warn", "migrate", "", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total == 0 || len(logs) == 0 {
		t.Fatal("安全迁移应记录一条日志，便于用户了解配置被调整过")
	}
}
