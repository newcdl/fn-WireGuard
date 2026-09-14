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
	s.applyInterfaceDefaults(it)
	if it.ListenPort == 0 {
		it.ListenPort = 51820
	}
	if err := s.validateInterface(ctx, it, 0); err != nil {
		return nil, 0, err
	}
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

// BackupPayload 是备份文件内容。
type BackupPayload struct {
	Version    string            `json:"version"`
	CreatedAt  time.Time         `json:"created_at"`
	IncludeKey bool              `json:"include_key"`
	Interfaces []model.Interface `json:"interfaces"`
	Peers      []model.Peer      `json:"peers"`
	Settings   map[string]string `json:"settings"`
}

// CreateBackup 生成备份文件并落盘到共享目录。
func (s *Service) CreateBackup(ctx context.Context, dir, note string, includeKey bool, a Actor) (*store.BackupRecord, error) {
	ifaces, err := s.Store.ListInterfaces(ctx)
	if err != nil {
		return nil, err
	}
	payload := BackupPayload{
		Version:    s.Version,
		CreatedAt:  time.Now(),
		IncludeKey: includeKey,
		Interfaces: []model.Interface{},
		Peers:      []model.Peer{},
	}
	settings, _ := s.Store.AllSettings(ctx)
	payload.Settings = settings
	for _, it := range ifaces {
		it.Revision = 0
		if !includeKey {
			it.PrivateKey = ""
		}
		payload.Interfaces = append(payload.Interfaces, it)
		peers, err := s.Store.ListPeers(ctx, it.ID)
		if err != nil {
			continue
		}
		for _, p := range peers {
			if !includeKey {
				p.PresharedKey = ""
				p.ClientPrivateKey = ""
			}
			payload.Peers = append(payload.Peers, p)
		}
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
		Kind:       "manual",
		Note:       note,
		IncludeKey: includeKey,
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

// RestoreBackup 从备份文件恢复配置（覆盖式）。
func (s *Service) RestoreBackup(ctx context.Context, dir string, id int64, a Actor) (int, error) {
	recs, err := s.Store.ListBackups(ctx)
	if err != nil {
		return 0, err
	}
	var target *store.BackupRecord
	for i := range recs {
		if recs[i].ID == id {
			target = &recs[i]
			break
		}
	}
	if target == nil {
		return 0, fmt.Errorf("备份记录不存在")
	}
	raw, err := os.ReadFile(filepath.Join(dir, target.Filename))
	if err != nil {
		return 0, fmt.Errorf("读取备份文件失败: %w", err)
	}
	var payload BackupPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return 0, fmt.Errorf("备份文件格式错误: %w", err)
	}
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
			// 不含密钥的备份需要重新生成预共享密钥以保持可用
			if psk, err := newPSK(); err == nil {
				src.PresharedKey = psk
			}
		}
		_ = s.Store.CreatePeer(ctx, &src)
	}
	s.audit(ctx, a, "backup.restore", "backup", fmt.Sprint(id), "", fmt.Sprint(n), "ok", target.Filename)
	_ = s.reconcile(ctx)
	return n, nil
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
