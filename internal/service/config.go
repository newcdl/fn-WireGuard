// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package service

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fnwg/internal/model"
	"fnwg/internal/store"
	"fnwg/internal/wgconf"
)

// ImportConf 从 wg-quick 配置文本导入接口及其节点。
func (s *Service) ImportConf(ctx context.Context, text, nameOverride string, a Actor) (*model.Interface, int, error) {
	f, err := wgconf.Parse(text)
	if err != nil {
		return nil, 0, fmt.Errorf("解析配置失败: %w", err)
	}
	name := strings.TrimSpace(nameOverride)
	if name == "" {
		name, err = s.nextInterfaceName(ctx)
		if err != nil {
			return nil, 0, err
		}
	}
	it := &model.Interface{
		Name:       name,
		UUID:       newUUID(),
		PrivateKey: f.Interface.PrivateKey,
		ListenPort: f.Interface.ListenPort,
		MTU:        f.Interface.MTU,
		Addresses:  f.Interface.Addresses,
		DNS:        f.Interface.DNS,
		DNSMode:    "client",
		RouteTable: "auto",
		PostUp:     strings.Join(f.Interface.PostUp, "\n"),
		PostDown:   strings.Join(f.Interface.PostDown, "\n"),
		Enabled:    true,
		Autostart:  true,
	}
	if f.Interface.Table != "" {
		it.RouteTable = f.Interface.Table
	}
	// 留空的地址与端口由 applyInterfaceDefaults 自动分配（并避开已有连接）
	if err := s.applyInterfaceDefaults(ctx, it, 0); err != nil {
		return nil, 0, err
	}
	if err := s.validateInterface(ctx, it, 0); err != nil {
		return nil, 0, err
	}
	s.snapshotBefore(ctx, "config.import", "导入配置「"+it.Name+"」")
	if err := s.Store.CreateInterface(ctx, it); err != nil {
		return nil, 0, err
	}

	count := 0
	for _, ps := range f.Peers {
		p := &model.Peer{
			InterfaceID:  it.ID,
			Name:         ps.Name,
			PublicKey:    ps.PublicKey,
			PresharedKey: ps.PresharedKey,
			AllowedIPs:   ps.AllowedIPs,
			Keepalive:    ps.Keepalive,
			Enabled:      true,
		}
		if ep := ps.Endpoint; ep != "" {
			if host, port, err := splitEndpoint(ep); err == nil {
				p.EndpointHost, p.EndpointPort = host, port
			}
		}
		if p.Name == "" {
			p.Name = "导入节点-" + shortKey(p.PublicKey)
		}
		if err := s.Store.CreatePeer(ctx, p); err != nil {
			continue
		}
		count++
	}
	s.audit(ctx, a, "config.import", "interface", fmt.Sprint(it.ID), "", it.Name, "ok", fmt.Sprintf("导入 %d 个节点", count))
	_ = s.reconcile(ctx)
	it.PrivateKey = ""
	return it, count, nil
}

// ExportInterface 导出单个接口的 wg-quick 配置。
func (s *Service) ExportInterface(ctx context.Context, id int64) (string, string, error) {
	name, text, err := s.InterfaceConf(ctx, id)
	if err != nil {
		return "", "", err
	}
	return name + ".conf", text, nil
}

// ExportAllZip 打包导出全部接口配置。
func (s *Service) ExportAllZip(ctx context.Context) ([]byte, string, error) {
	ifaces, err := s.Store.ListInterfaces(ctx)
	if err != nil {
		return nil, "", err
	}
	buf := new(bytes.Buffer)
	zw := zip.NewWriter(buf)
	for _, it := range ifaces {
		peers, err := s.Store.ListPeers(ctx, it.ID)
		if err != nil {
			continue
		}
		w, err := zw.Create(it.Name + ".conf")
		if err != nil {
			continue
		}
		_, _ = w.Write([]byte(wgconf.RenderServer(&it, peers)))
	}
	if err := zw.Close(); err != nil {
		return nil, "", err
	}
	return buf.Bytes(), fmt.Sprintf("fn-wireguard-%s.zip", time.Now().Format("20060102-150405")), nil
}

// BackupUser 是备份里的账号快照。
//
// 不复用 model.User：那里 PasswordHash / TOTPSecret 打了 `json:"-"`，
// 目的是不让它们出现在 /users 的接口响应里；但备份恰恰需要这两项，
// 否则还原后管理员密码与二次验证密钥就丢了，全量备份名不副实。
type BackupUser struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
	TOTPSecret   string `json:"totp_secret,omitempty"`
	Role         string `json:"role"`
	Status       int    `json:"status"` // 1 启用 0 禁用
}

// BackupPayload 是备份文件内容（全量：连接、设备、设置、内网域名、账号与密钥）。
type BackupPayload struct {
	Version    string            `json:"version"`
	CreatedAt  time.Time         `json:"created_at"`
	IncludeKey bool              `json:"include_key"` // 新备份恒为 true，仅用于兼容读取旧备份
	Interfaces []model.Interface `json:"interfaces"`
	Peers      []model.Peer      `json:"peers"`
	Settings   map[string]string `json:"settings"`
	Users      []BackupUser      `json:"users"`
	// HasDNSRecords 标记这份文件是否带有内网域名段。
	//
	// 老备份没有这个字段，此时绝不能把 dns_record 表清空——
	// 否则「从旧备份还原」会顺手删掉用户后来加的域名映射，
	// 而备份里根本没这些东西，等于凭空丢配置。只有明确带段落的新文件才覆盖。
	HasDNSRecords bool              `json:"has_dns_records,omitempty"`
	DNSRecords    []store.DNSRecord `json:"dns_records,omitempty"`
}

// buildBackupPayload 采集当前配置生成备份内容。
//
// includeUsers 控制是否带上账号（含密码哈希与 TOTP 密钥）：
//   - 全量备份为 true，还原后管理员密码与二次验证状态都能回来；
//   - 配置快照为 false，回滚配置时不会顺带把账号安全设置退回旧值。
//
// 运行时字段（上下线、实时速率、握手时间、派生的公钥等）一律清零：
// 它们每几秒就变，混进文件不仅让快照无法做「内容相同即跳过」的去重，
// 还会让快照之间的差异对比全是噪声。
func (s *Service) buildBackupPayload(ctx context.Context, includeUsers bool) (*BackupPayload, error) {
	ifaces, err := s.Store.ListInterfaces(ctx)
	if err != nil {
		return nil, err
	}
	payload := &BackupPayload{
		Version:    s.Version,
		CreatedAt:  time.Now(),
		IncludeKey: true,
		Interfaces: []model.Interface{},
		Peers:      []model.Peer{},
		Users:      []BackupUser{},
	}
	settings, err := s.Store.AllSettings(ctx)
	if err != nil {
		return nil, err
	}
	payload.Settings = settings
	for _, it := range ifaces {
		it.Revision = 0
		it.PublicKey, it.Backend = "", ""
		it.Up, it.PeerCount, it.PeerOnline = false, 0, 0
		it.RxBytes, it.TxBytes, it.RxRate, it.TxRate = 0, 0, 0, 0
		payload.Interfaces = append(payload.Interfaces, it)
		peers, err := s.Store.ListPeers(ctx, it.ID)
		if err != nil {
			continue
		}
		for i := range peers {
			peers[i].Online = false
			peers[i].LastHandshake = time.Time{}
			peers[i].Endpoint = ""
			peers[i].RxBytes, peers[i].TxBytes = 0, 0
			peers[i].RxRate, peers[i].TxRate = 0, 0
			peers[i].ConfigStale = false
		}
		payload.Peers = append(payload.Peers, peers...)
	}
	// 内网域名映射同样属于「配置」：不回滚它，就会出现「配置已回到过去，
	// 但设备用主机名访问的地址还是三天前那一版」这种半回滚状态。
	if recs, err := s.Store.ListDNSRecords(ctx); err == nil {
		payload.HasDNSRecords = true
		payload.DNSRecords = recs
	}
	if !includeUsers {
		return payload, nil
	}
	users, err := s.Store.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	for _, u := range users {
		payload.Users = append(payload.Users, BackupUser{
			Username:     u.Username,
			PasswordHash: u.PasswordHash,
			TOTPSecret:   u.TOTPSecret,
			Role:         u.Role,
			Status:       u.Status,
		})
	}
	return payload, nil
}

// CreateBackup 生成全量备份并落盘到共享目录。
//
// 全量意味着：连接私钥、设备预共享密钥与代管私钥、全部设置、内网域名、全部账号
// （含管理员密码哈希与 TOTP 密钥）一并写入，还原时能原样恢复。
func (s *Service) CreateBackup(ctx context.Context, dir, note string, a Actor) (*store.BackupRecord, error) {
	payload, err := s.buildBackupPayload(ctx, true)
	if err != nil {
		return nil, err
	}
	raw, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o770); err != nil {
		return nil, err
	}
	filename := fmt.Sprintf("fn-wireguard-backup-%s.json", time.Now().Format("20060102-150405"))
	path := filepath.Join(dir, filename)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	rec := &store.BackupRecord{
		Filename:   filename,
		Size:       int64(len(raw)),
		SHA256:     hex.EncodeToString(sum[:]),
		Kind:       store.BackupKindManual,
		Note:       note,
		IncludeKey: true,
	}
	if err := s.Store.CreateBackupRecord(ctx, rec); err != nil {
		return nil, err
	}
	s.audit(ctx, a, "backup.create", "backup", filename, "", fmt.Sprint(len(raw)), "ok", note)
	return rec, nil
}

// ListBackups 返回备份记录。
func (s *Service) ListBackups(ctx context.Context) ([]store.BackupRecord, error) {
	return s.Store.ListBackups(ctx)
}

// DeleteBackup 删除备份文件与记录。
func (s *Service) DeleteBackup(ctx context.Context, dir string, id int64, a Actor) error {
	recs, err := s.Store.ListBackups(ctx)
	if err != nil {
		return err
	}
	for _, r := range recs {
		if r.ID == id {
			_ = os.Remove(filepath.Join(dir, r.Filename))
			break
		}
	}
	if err := s.Store.DeleteBackupRecord(ctx, id); err != nil {
		return err
	}
	s.audit(ctx, a, "backup.delete", "backup", fmt.Sprint(id), "", "", "ok", "")
	return nil
}

// DownloadBackup 返回备份文件原始内容与文件名，供界面下载（导出备份）。
func (s *Service) DownloadBackup(ctx context.Context, dir string, id int64) ([]byte, string, error) {
	recs, err := s.Store.ListBackups(ctx)
	if err != nil {
		return nil, "", err
	}
	for i := range recs {
		if recs[i].ID == id {
			raw, err := os.ReadFile(filepath.Join(dir, recs[i].Filename))
			if err != nil {
				return nil, "", fmt.Errorf("读取备份文件失败: %w", err)
			}
			return raw, recs[i].Filename, nil
		}
	}
	return nil, "", fmt.Errorf("备份记录不存在")
}

// ImportBackup 导入一份备份文件：校验内容后落盘到共享目录并登记记录，随后即可在列表里还原。
//
// 只登记、不立刻还原——导入后由用户决定是否点「还原」，避免误操作直接把线上配置覆盖。
func (s *Service) ImportBackup(ctx context.Context, dir string, raw []byte, filename, note string, a Actor) (*store.BackupRecord, error) {
	var payload BackupPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, fmt.Errorf("不是有效的备份文件：%w", err)
	}
	if payload.Version == "" && len(payload.Interfaces) == 0 && len(payload.Peers) == 0 &&
		len(payload.Settings) == 0 && len(payload.Users) == 0 {
		return nil, fmt.Errorf("备份文件缺少有效内容")
	}
	if err := os.MkdirAll(dir, 0o770); err != nil {
		return nil, err
	}
	// 文件名安全化：只接受纯文件名，出现路径成分一律回退到时间戳命名，杜绝路径穿越。
	name := strings.TrimSpace(filename)
	if name == "" || filepath.Base(name) != name || strings.ContainsAny(name, `/\`) {
		name = fmt.Sprintf("fn-wireguard-backup-%s.json", time.Now().Format("20060102-150405"))
	}
	if !strings.HasSuffix(strings.ToLower(name), ".json") {
		name += ".json"
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	rec := &store.BackupRecord{
		Filename:   name,
		Size:       int64(len(raw)),
		SHA256:     hex.EncodeToString(sum[:]),
		Kind:       store.BackupKindImported,
		Note:       note,
		IncludeKey: payload.IncludeKey,
	}
	if err := s.Store.CreateBackupRecord(ctx, rec); err != nil {
		return nil, err
	}
	s.audit(ctx, a, "backup.import", "backup", name, "", fmt.Sprint(len(raw)), "ok", note)
	return rec, nil
}

// LoadBackupPayload 读取备份文件内容（不落任何改动），供还原与差异对比使用。
func (s *Service) LoadBackupPayload(ctx context.Context, dir string, id int64) (*BackupPayload, *store.BackupRecord, error) {
	recs, err := s.Store.ListBackups(ctx)
	if err != nil {
		return nil, nil, err
	}
	var target *store.BackupRecord
	for i := range recs {
		if recs[i].ID == id {
			target = &recs[i]
			break
		}
	}
	if target == nil {
		return nil, nil, fmt.Errorf("记录不存在")
	}
	raw, err := os.ReadFile(filepath.Join(dir, target.Filename))
	if err != nil {
		return nil, nil, fmt.Errorf("读取文件失败: %w", err)
	}
	var payload BackupPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, nil, fmt.Errorf("文件格式错误: %w", err)
	}
	return &payload, target, nil
}

// ListUserBackups 返回用户可见的备份（manual/imported），不含自动快照。
//
// 自动快照每次改配置都会新增一条，混进备份列表会把用户自己存的那几份顶到看不见的地方，
// 所以两个列表各自分流：备份页只看备份，快照页只看快照。
func (s *Service) ListUserBackups(ctx context.Context) ([]store.BackupRecord, error) {
	return s.Store.ListBackupsByKind(ctx, store.BackupKindManual, store.BackupKindImported)
}

// RestoreBackup 从备份文件全量恢复（覆盖式）：连接、设备、设置、内网域名与账号一并还原。
func (s *Service) RestoreBackup(ctx context.Context, dir string, id int64, a Actor) (int, error) {
	payload, target, err := s.LoadBackupPayload(ctx, dir, id)
	if err != nil {
		return 0, err
	}
	// 还原是破坏性操作，先给当前状态留一份快照：还原错了还能滚回来。
	s.snapshotBefore(ctx, "backup.restore", "还原备份前："+target.Filename)
	n, err := s.applyBackupPayload(ctx, payload, true)
	if err != nil {
		return n, err
	}
	s.audit(ctx, a, "backup.restore", "backup", fmt.Sprint(id), "", fmt.Sprint(n), "ok", target.Filename)
	_ = s.reconcile(ctx)
	return n, nil
}

// applyBackupPayload 把备份内容覆盖式写入数据库，返回恢复的接口数量。
//
// restoreAccounts 为假时不动账号：配置快照回滚走的就是这条路。
// 「回滚配置」若顺带把管理员密码、二次验证密钥退回旧值，那不是恢复而是安全倒退
// ——旧快照里的密码可能早已因为泄露而改掉。
func (s *Service) applyBackupPayload(ctx context.Context, payload *BackupPayload, restoreAccounts bool) (int, error) {
	if _, err := s.Store.DB().ExecContext(ctx, `DELETE FROM wg_interface`); err != nil {
		return 0, err
	}
	if _, err := s.Store.DB().ExecContext(ctx, `DELETE FROM wg_peer`); err != nil {
		return 0, err
	}
	idMap := map[int64]int64{}
	n := 0
	for _, it := range payload.Interfaces {
		src := it
		src.ID = 0
		if src.PrivateKey == "" {
			// 只有旧版「不含密钥」的备份才会出现空私钥，这种连接无法恢复
			continue
		}
		if err := s.Store.CreateInterface(ctx, &src); err != nil {
			continue
		}
		idMap[it.ID] = src.ID
		n++
	}
	for _, p := range payload.Peers {
		src := p
		src.ID = 0
		if nid, ok := idMap[p.InterfaceID]; ok {
			src.InterfaceID = nid
		} else {
			continue
		}
		if src.PresharedKey == "" && !payload.IncludeKey {
			// 旧版不含密钥的备份需要重新生成预共享密钥以保持可用
			if psk, err := newPSK(); err == nil {
				src.PresharedKey = psk
			}
		}
		_ = s.Store.CreatePeer(ctx, &src)
	}
	// 恢复设置：全量备份包含全部设置项，逐项覆盖写入。
	for k, v := range payload.Settings {
		if k == "" {
			continue
		}
		if err := s.Store.SetSetting(ctx, k, v); err != nil {
			return n, fmt.Errorf("恢复设置 %s 失败: %w", k, err)
		}
	}
	if payload.HasDNSRecords {
		if err := s.replaceDNSRecords(ctx, payload.DNSRecords); err != nil {
			return n, fmt.Errorf("恢复内网域名失败: %w", err)
		}
	}
	if !restoreAccounts {
		return n, nil
	}
	// 恢复账号（含管理员密码哈希与 TOTP）。
	// 账号恢复失败不应阻断网络配置恢复，但必须留痕，否则用户以为密码已经还原、实则没有。
	if err := s.restoreUsers(ctx, payload.Users); err != nil {
		_ = s.Store.AddLog(ctx, "warn", "backup", "备份还原时账号恢复失败", err.Error())
	}
	return n, nil
}

// replaceDNSRecords 用给定记录整体替换内网域名表（覆盖式回滚语义）。
func (s *Service) replaceDNSRecords(ctx context.Context, recs []store.DNSRecord) error {
	if _, err := s.Store.DB().ExecContext(ctx, `DELETE FROM dns_record`); err != nil {
		return err
	}
	for _, r := range recs {
		src := r
		src.ID = 0
		if strings.TrimSpace(src.Name) == "" {
			continue
		}
		if err := s.Store.CreateDNSRecord(ctx, &src); err != nil {
			return err
		}
	}
	return nil
}

// restoreUsers 按备份恢复账号。按用户名 upsert：同名的走 UPDATE（保留主键，
// 正在执行还原的会话不会因为用户被删重建而失效），不存在的走 INSERT。
func (s *Service) restoreUsers(ctx context.Context, users []BackupUser) error {
	existing, err := s.Store.ListUsers(ctx)
	if err != nil {
		return err
	}
	byName := map[string]*model.User{}
	for i := range existing {
		byName[existing[i].Username] = &existing[i]
	}
	for _, bu := range users {
		if bu.Username == "" {
			continue
		}
		if cur, ok := byName[bu.Username]; ok {
			cur.PasswordHash = bu.PasswordHash
			cur.TOTPSecret = bu.TOTPSecret
			cur.Role = bu.Role
			if bu.Status != 0 {
				cur.Status = bu.Status
			}
			if err := s.Store.UpdateUser(ctx, cur); err != nil {
				return err
			}
			continue
		}
		status := bu.Status
		if status == 0 {
			status = 1 // 备份里缺省状态一律视为启用，避免误把账号恢复成禁用
		}
		if err := s.Store.CreateUser(ctx, &model.User{
			Username:     bu.Username,
			PasswordHash: bu.PasswordHash,
			TOTPSecret:   bu.TOTPSecret,
			Role:         bu.Role,
			Status:       status,
		}); err != nil {
			return err
		}
	}
	return nil
}

func shortKey(k string) string {
	if len(k) > 8 {
		return k[:8]
	}
	return k
}

func splitEndpoint(ep string) (string, int, error) {
	i := strings.LastIndex(ep, ":")
	if i <= 0 {
		return "", 0, fmt.Errorf("endpoint 非法")
	}
	host := strings.Trim(ep[:i], "[]")
	var port int
	if _, err := fmt.Sscanf(ep[i+1:], "%d", &port); err != nil {
		return "", 0, err
	}
	return host, port, nil
}
