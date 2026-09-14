package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"fnwg/internal/model"
)

// ErrNotFound 表示目标记录不存在。
var ErrNotFound = errors.New("记录不存在")

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func jsonStrings(s string) []string {
	out := []string{}
	if s == "" {
		return out
	}
	_ = json.Unmarshal([]byte(s), &out)
	return out
}

// ---------------------------------------------------------------- 接口

const ifaceCols = `id,name,uuid,private_key,listen_port,fwmark,mtu,addresses,dns,dns_mode,route_table,
	pre_up,post_up,pre_down,post_down,enabled,autostart,revision,created_at,updated_at`

func (s *Store) scanInterface(sc interface{ Scan(...any) error }) (*model.Interface, error) {
	var (
		it        model.Interface
		privKey   []byte
		addrs     string
		dns       string
		enabled   int
		autostart int
		createdAt string
		updatedAt string
	)
	err := sc.Scan(&it.ID, &it.Name, &it.UUID, &privKey, &it.ListenPort, &it.FWMark, &it.MTU,
		&addrs, &dns, &it.DNSMode, &it.RouteTable,
		&it.PreUp, &it.PostUp, &it.PreDown, &it.PostDown,
		&enabled, &autostart, &it.Revision, &createdAt, &updatedAt)
	if err != nil {
		return nil, err
	}
	it.Addresses = jsonStrings(addrs)
	it.DNS = jsonStrings(dns)
	it.Enabled = enabled == 1
	it.Autostart = autostart == 1
	it.CreatedAt = parseTS(createdAt)
	it.UpdatedAt = parseTS(updatedAt)
	if s.box != nil && len(privKey) > 0 {
		if v, err := s.box.OpenString(privKey); err == nil {
			it.PrivateKey = v
		}
	}
	return &it, nil
}

// ListInterfaces 返回全部接口。
func (s *Store) ListInterfaces(ctx context.Context) ([]model.Interface, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+ifaceCols+` FROM wg_interface ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Interface{}
	for rows.Next() {
		it, err := s.scanInterface(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *it)
	}
	return out, rows.Err()
}

// GetInterface 按主键查询。
func (s *Store) GetInterface(ctx context.Context, id int64) (*model.Interface, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+ifaceCols+` FROM wg_interface WHERE id=?`, id)
	it, err := s.scanInterface(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return it, err
}

// GetInterfaceByName 按名称查询。
func (s *Store) GetInterfaceByName(ctx context.Context, name string) (*model.Interface, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+ifaceCols+` FROM wg_interface WHERE name=?`, name)
	it, err := s.scanInterface(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return it, err
}

// CreateInterface 落库新接口。
func (s *Store) CreateInterface(ctx context.Context, it *model.Interface) error {
	key, err := s.box.SealString(it.PrivateKey)
	if err != nil {
		return err
	}
	now := time.Now()
	it.CreatedAt, it.UpdatedAt = now, now
	it.Revision = 1
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO wg_interface(name,uuid,private_key,listen_port,fwmark,mtu,addresses,dns,dns_mode,route_table,
		 pre_up,post_up,pre_down,post_down,enabled,autostart,revision,created_at,updated_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		it.Name, it.UUID, key, it.ListenPort, it.FWMark, it.MTU,
		mustJSON(it.Addresses), mustJSON(it.DNS), it.DNSMode, it.RouteTable,
		it.PreUp, it.PostUp, it.PreDown, it.PostDown,
		b2i(it.Enabled), b2i(it.Autostart), it.Revision, ts(now), ts(now))
	if err != nil {
		return err
	}
	it.ID, _ = res.LastInsertId()
	return nil
}

// UpdateInterface 全量更新并把 revision 加一（驱动幂等收敛）。
func (s *Store) UpdateInterface(ctx context.Context, it *model.Interface) error {
	key, err := s.box.SealString(it.PrivateKey)
	if err != nil {
		return err
	}
	now := time.Now()
	it.UpdatedAt = now
	res, err := s.db.ExecContext(ctx,
		`UPDATE wg_interface SET name=?,private_key=?,listen_port=?,fwmark=?,mtu=?,addresses=?,dns=?,dns_mode=?,
		 route_table=?,pre_up=?,post_up=?,pre_down=?,post_down=?,enabled=?,autostart=?,revision=revision+1,updated_at=?
		 WHERE id=?`,
		it.Name, key, it.ListenPort, it.FWMark, it.MTU, mustJSON(it.Addresses), mustJSON(it.DNS), it.DNSMode,
		it.RouteTable, it.PreUp, it.PostUp, it.PreDown, it.PostDown, b2i(it.Enabled), b2i(it.Autostart), ts(now), it.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	it.Revision++
	return nil
}

// DeleteInterface 删除接口及其全部 Peer。
func (s *Store) DeleteInterface(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM wg_interface WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	_, _ = s.db.ExecContext(ctx, `DELETE FROM wg_peer WHERE interface_id=?`, id)
	return nil
}

// InterfaceNames 返回已存在的接口名集合，用于生成不冲突的默认名称。
func (s *Store) InterfaceNames(ctx context.Context) (map[string]bool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name FROM wg_interface`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out[n] = true
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------- Peer

const peerCols = `p.id,p.interface_id,IFNULL(i.name,''),p.name,p.public_key,p.preshared_key,p.client_priv,
	IFNULL(p.route_mode,'lan'),IFNULL(p.client_ips,'[]'),p.endpoint_host,
	p.endpoint_port,p.allowed_ips,p.keepalive,p.group_tag,p.remark,p.quota_rx,p.quota_tx,p.expire_at,p.enabled,
	p.created_at,p.updated_at`

const peerFrom = ` FROM wg_peer p LEFT JOIN wg_interface i ON i.id = p.interface_id`

func (s *Store) scanPeer(sc interface{ Scan(...any) error }) (*model.Peer, error) {
	var (
		p         model.Peer
		psk       []byte
		clientKey []byte
		clientIPs string
		allowed   string
		expireAt  sql.NullString
		enabled   int
		createdAt string
		updatedAt string
	)
	err := sc.Scan(&p.ID, &p.InterfaceID, &p.InterfaceName, &p.Name, &p.PublicKey, &psk, &clientKey,
		&p.RouteMode, &clientIPs, &p.EndpointHost,
		&p.EndpointPort, &allowed, &p.Keepalive, &p.GroupTag, &p.Remark, &p.QuotaRx, &p.QuotaTx, &expireAt,
		&enabled, &createdAt, &updatedAt)
	if err != nil {
		return nil, err
	}
	p.AllowedIPs = jsonStrings(allowed)
	p.ClientAllowedIPs = jsonStrings(clientIPs)
	if p.RouteMode == "" {
		p.RouteMode = model.RouteModeLAN
	}
	p.ExpireAt = parseTSNull(expireAt)
	p.Enabled = enabled == 1
	p.CreatedAt = parseTS(createdAt)
	p.UpdatedAt = parseTS(updatedAt)
	if s.box != nil && len(psk) > 0 {
		if v, err := s.box.OpenString(psk); err == nil {
			p.PresharedKey = v
		}
	}
	if s.box != nil && len(clientKey) > 0 {
		if v, err := s.box.OpenString(clientKey); err == nil {
			p.ClientPrivateKey = v
		}
	}
	return &p, nil
}

// ListPeers 返回指定接口（interfaceID<=0 表示全部）的节点。
func (s *Store) ListPeers(ctx context.Context, interfaceID int64) ([]model.Peer, error) {
	q := `SELECT ` + peerCols + peerFrom
	args := []any{}
	if interfaceID > 0 {
		q += ` WHERE p.interface_id=?`
		args = append(args, interfaceID)
	}
	q += ` ORDER BY p.id`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Peer{}
	for rows.Next() {
		p, err := s.scanPeer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// GetPeer 按主键查询节点。
func (s *Store) GetPeer(ctx context.Context, id int64) (*model.Peer, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+peerCols+peerFrom+` WHERE p.id=?`, id)
	p, err := s.scanPeer(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return p, err
}

// CreatePeer 落库新节点。
func (s *Store) CreatePeer(ctx context.Context, p *model.Peer) error {
	psk, err := s.box.SealString(p.PresharedKey)
	if err != nil {
		return err
	}
	clientKey, err := s.box.SealString(p.ClientPrivateKey)
	if err != nil {
		return err
	}
	if p.RouteMode == "" {
		p.RouteMode = model.RouteModeLAN
	}
	now := time.Now()
	p.CreatedAt, p.UpdatedAt = now, now
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO wg_peer(interface_id,name,public_key,preshared_key,client_priv,route_mode,client_ips,
		 endpoint_host,endpoint_port,allowed_ips,
		 keepalive,group_tag,remark,quota_rx,quota_tx,expire_at,enabled,created_at,updated_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		p.InterfaceID, p.Name, p.PublicKey, psk, clientKey, p.RouteMode, mustJSON(p.ClientAllowedIPs),
		p.EndpointHost, p.EndpointPort, mustJSON(p.AllowedIPs),
		p.Keepalive, p.GroupTag, p.Remark, p.QuotaRx, p.QuotaTx, expireArg(p.ExpireAt), b2i(p.Enabled), ts(now), ts(now))
	if err != nil {
		return err
	}
	p.ID, _ = res.LastInsertId()
	return nil
}

func expireArg(t *time.Time) any {
	if t == nil || t.IsZero() {
		return nil
	}
	return ts(*t)
}

// UpdatePeer 全量更新节点。
func (s *Store) UpdatePeer(ctx context.Context, p *model.Peer) error {
	psk, err := s.box.SealString(p.PresharedKey)
	if err != nil {
		return err
	}
	clientKey, err := s.box.SealString(p.ClientPrivateKey)
	if err != nil {
		return err
	}
	if p.RouteMode == "" {
		p.RouteMode = model.RouteModeLAN
	}
	now := time.Now()
	p.UpdatedAt = now
	res, err := s.db.ExecContext(ctx,
		`UPDATE wg_peer SET interface_id=?,name=?,public_key=?,preshared_key=?,client_priv=?,route_mode=?,client_ips=?,
		 endpoint_host=?,endpoint_port=?,
		 allowed_ips=?,keepalive=?,group_tag=?,remark=?,quota_rx=?,quota_tx=?,expire_at=?,enabled=?,updated_at=?
		 WHERE id=?`,
		p.InterfaceID, p.Name, p.PublicKey, psk, clientKey, p.RouteMode, mustJSON(p.ClientAllowedIPs),
		p.EndpointHost, p.EndpointPort,
		mustJSON(p.AllowedIPs), p.Keepalive, p.GroupTag, p.Remark, p.QuotaRx, p.QuotaTx,
		expireArg(p.ExpireAt), b2i(p.Enabled), ts(now), p.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeletePeer 删除节点。
func (s *Store) DeletePeer(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM wg_peer WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// BatchSetPeerEnabled 批量启用/禁用节点。
func (s *Store) BatchSetPeerEnabled(ctx context.Context, ids []int64, enabled bool) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	q := `UPDATE wg_peer SET enabled=?, updated_at=? WHERE id IN (` + placeholders(len(ids)) + `)`
	args := []any{b2i(enabled), ts(time.Now())}
	for _, id := range ids {
		args = append(args, id)
	}
	res, err := s.db.ExecContext(ctx, q, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// BatchDeletePeers 批量删除节点。
func (s *Store) BatchDeletePeers(ctx context.Context, ids []int64) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	q := `DELETE FROM wg_peer WHERE id IN (` + placeholders(len(ids)) + `)`
	args := make([]any, 0, len(ids))
	for _, id := range ids {
		args = append(args, id)
	}
	res, err := s.db.ExecContext(ctx, q, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func placeholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

// ---------------------------------------------------------------- 统计

// SaveStatSamples 批量写入历史采样。
func (s *Store) SaveStatSamples(ctx context.Context, samples []model.StatSample) error {
	if len(samples) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO wg_peer_stat(interface_id,public_key,ts,rx_bytes,tx_bytes) VALUES(?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, sm := range samples {
		if _, err := stmt.ExecContext(ctx, sm.InterfaceID, sm.PeerPublicKey, sm.Ts.Unix(), sm.RxBytes, sm.TxBytes); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// PruneStats 删除过期的原始采样（默认保留 24 小时）。
func (s *Store) PruneStats(ctx context.Context, olderThan time.Time) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM wg_peer_stat WHERE ts < ?`, olderThan.Unix())
	return err
}

// PeerHistory 返回某节点最近的时间序列，用于前端图表。
func (s *Store) PeerHistory(ctx context.Context, interfaceID int64, publicKey string, since time.Time, limit int) ([][3]float64, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT ts,rx_bytes,tx_bytes FROM wg_peer_stat WHERE interface_id=? AND public_key=? AND ts>=? ORDER BY ts LIMIT ?`,
		interfaceID, publicKey, since.Unix(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := [][3]float64{}
	for rows.Next() {
		var t, rx, tx int64
		if err := rows.Scan(&t, &rx, &tx); err != nil {
			return nil, err
		}
		out = append(out, [3]float64{float64(t), float64(rx), float64(tx)})
	}
	return out, rows.Err()
}
