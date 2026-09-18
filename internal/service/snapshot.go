// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"fnwg/internal/model"
	"fnwg/internal/store"
)

// SettingSnapshotKeep 是自动快照的保留份数设置项。
//
// 快照不能无限堆积：改一次配置就是一份全量 JSON，一年下来能把共享目录塞满，
// 而用户几乎只会回滚到最近几次。默认保留 50 份，超出后从最旧的开始清理。
const SettingSnapshotKeep = "snapshot_keep"

const defaultSnapshotKeep = 50

// maxSnapshotKeep 是保留份数的上限。放太大等于没有清理，还会让每次列表都读一长串记录。
const maxSnapshotKeep = 500

// errSnapshotDirMissing 表示当前进程没有配置快照目录。
//
// CLI 子命令与单元测试里不会设置它，此时自动留档直接跳过：
// 快照是给 Web 界面用的后手，命令行改配置不该因此报错。
var errSnapshotDirMissing = errors.New("快照目录未配置")

// SetSnapshotDir 设置快照落盘目录。与备份共用共享目录，靠文件名前缀与记录类型区分。
func (s *Service) SetSnapshotDir(dir string) {
	s.snapshotDir = strings.TrimSpace(dir)
}

// SnapshotKeep 返回当前配置的快照保留份数。
func (s *Service) SnapshotKeep(ctx context.Context) int {
	raw := strings.TrimSpace(s.Store.GetSetting(ctx, SettingSnapshotKeep, ""))
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return defaultSnapshotKeep
	}
	if n > maxSnapshotKeep {
		return maxSnapshotKeep
	}
	return n
}

// ListSnapshots 返回全部配置快照，按时间倒序。
func (s *Service) ListSnapshots(ctx context.Context) ([]store.BackupRecord, error) {
	return s.Store.ListBackupsByKind(ctx, store.BackupKindAuto)
}

// snapshotBefore 在关键配置变更前留一份快照，失败绝不阻断用户操作。
//
// 为什么不能因为快照失败就拒绝操作：快照是「后悔药」，不是锁。
// 但失败必须留日志——悄悄失败比没有快照更糟：用户以为能回滚，出事时才发现没有。
func (s *Service) snapshotBefore(ctx context.Context, action, note string) {
	if _, err := s.takeSnapshot(ctx, action, note); err != nil {
		if errors.Is(err, errSnapshotDirMissing) {
			return
		}
		s.Log.Warn("自动快照失败", "action", action, "err", err)
		_ = s.Store.AddLog(ctx, "warn", "snapshot",
			"自动快照失败，本次改动之后无法在快照列表里回滚", action+"："+err.Error())
	}
}

// takeSnapshot 生成一份配置快照并落盘登记。
//
// 返回 (nil, nil) 表示本次被去重跳过——当前配置与上一份快照完全相同。
func (s *Service) takeSnapshot(ctx context.Context, action, note string) (*store.BackupRecord, error) {
	if s.snapshotDir == "" {
		return nil, errSnapshotDirMissing
	}
	// 串行化：并发请求同时改配置时，两份快照可能抢同一个文件名，
	// 也可能都读到「还没有更早的快照」而各自写一份内容相同的文件。
	s.snapMu.Lock()
	defer s.snapMu.Unlock()

	// 快照只含配置、不含账号：回滚配置不该把密码与二次验证状态一起退回旧值。
	payload, err := s.buildBackupPayload(ctx, false)
	if err != nil {
		return nil, err
	}
	raw, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	sha := hex.EncodeToString(sum[:])
	if s.sameAsLatestSnapshot(ctx, payload) {
		// 配置与上一份快照一致：这次操作没有真正改变配置
		//（改了又改回来，或重复提交了同一个请求），再堆一份同样的文件没有意义。
		return nil, nil
	}
	if err := os.MkdirAll(s.snapshotDir, 0o770); err != nil {
		return nil, err
	}
	now := time.Now()
	// 文件名带毫秒：同一秒内的连续两次改动能各留各的档，不会后一份覆盖前一份。
	filename := fmt.Sprintf("fn-wireguard-snapshot-%s.json", now.Format("20060102-150405.000"))
	path := filepath.Join(s.snapshotDir, filename)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return nil, err
	}
	rec := &store.BackupRecord{
		Filename:   filename,
		Size:       int64(len(raw)),
		SHA256:     sha,
		Kind:       store.BackupKindAuto,
		Note:       fmt.Sprintf("%s · %s", note, describePayload(payload)),
		IncludeKey: true,
	}
	if err := s.Store.CreateBackupRecord(ctx, rec); err != nil {
		_ = os.Remove(path) // 登记失败就别留下无人认领的文件
		return nil, err
	}
	s.pruneSnapshots(ctx)
	s.Log.Debug("已留配置快照", "action", action, "file", filename)
	return rec, nil
}

// sameAsLatestSnapshot 判断当前配置是否与最近一份快照实质相同。
//
// 不能直接拿文件的 SHA-256 比对：文件里带着采集时间（created_at），
// 每次生成都不同，这样比等于永远「有变化」，去重会彻底失效。
// 所以这里把文件读回来，只比对接口/设备/域名/设置这几段配置内容。
func (s *Service) sameAsLatestSnapshot(ctx context.Context, payload *BackupPayload) bool {
	recs, err := s.Store.ListBackupsByKind(ctx, store.BackupKindAuto)
	if err != nil || len(recs) == 0 {
		return false
	}
	raw, err := os.ReadFile(filepath.Join(s.snapshotDir, recs[0].Filename))
	if err != nil {
		return false
	}
	var prev BackupPayload
	if err := json.Unmarshal(raw, &prev); err != nil {
		return false
	}
	// 当前配置是直接构造出来的，空切片/空 map 可能是 nil；而快照是从文件反序列化来的，
	// 同样为空时可能是非 nil 的 [] 或 {}，两者 Marshal 出来一个 null 一个 []，
	// 内容一样却会被判成「变了」。让当前负载也走一遍 JSON 解码，保证两边归一化一致。
	curRaw, err := json.Marshal(payload)
	if err != nil {
		return false
	}
	var cur BackupPayload
	if err := json.Unmarshal(curRaw, &cur); err != nil {
		return false
	}
	return snapshotFingerprint(&prev) == snapshotFingerprint(&cur)
}

// snapshotFingerprint 把负载压成「只含配置」的稳定字符串，用于判断两次快照是否实质相同。
//
// 刻意排除 created_at 与 version：前者是采集时刻、后者是软件版本，
// 都不属于用户改了什么，混进来会让去重失效。
func snapshotFingerprint(p *BackupPayload) string {
	raw, err := json.Marshal(struct {
		Interfaces []model.Interface
		Peers      []model.Peer
		DNSRecords []store.DNSRecord
		Settings   map[string]string
	}{
		Interfaces: p.Interfaces,
		Peers:      p.Peers,
		DNSRecords: p.DNSRecords,
		Settings:   p.Settings,
	})
	if err != nil {
		return ""
	}
	return string(raw)
}

// pruneSnapshots 按保留份数清理最旧的快照（连同文件）。
func (s *Service) pruneSnapshots(ctx context.Context) {
	recs, err := s.Store.ListBackupsByKind(ctx, store.BackupKindAuto)
	if err != nil {
		return
	}
	keep := s.SnapshotKeep(ctx)
	if len(recs) <= keep {
		return
	}
	for _, r := range recs[keep:] {
		_ = os.Remove(filepath.Join(s.snapshotDir, r.Filename))
		if err := s.Store.DeleteBackupRecord(ctx, r.ID); err != nil {
			s.Log.Warn("清理过期快照失败", "file", r.Filename, "err", err)
		}
	}
	s.Log.Debug("已清理过期快照", "removed", len(recs)-keep, "keep", keep)
}

// DeleteSnapshot 删除一份快照及其文件。
func (s *Service) DeleteSnapshot(ctx context.Context, dir string, id int64, a Actor) error {
	recs, err := s.Store.ListBackupsByKind(ctx, store.BackupKindAuto)
	if err != nil {
		return err
	}
	found := false
	for _, r := range recs {
		if r.ID == id {
			found = true
			_ = os.Remove(filepath.Join(dir, r.Filename))
			break
		}
	}
	if !found {
		return fmt.Errorf("快照不存在")
	}
	if err := s.Store.DeleteBackupRecord(ctx, id); err != nil {
		return err
	}
	s.audit(ctx, a, "snapshot.delete", "snapshot", fmt.Sprint(id), "", "", "ok", "")
	return nil
}

// describePayload 用一句话说明快照里有多少东西，直接写进备注供列表展示，
// 免得为了「这份快照包含几条连接」把每个文件都读一遍。
func describePayload(p *BackupPayload) string {
	return fmt.Sprintf("%d 连接 / %d 设备 / %d 域名", len(p.Interfaces), len(p.Peers), len(p.DNSRecords))
}

// settingsNote 给出设置变更的快照备注。只出现键名，不带取值。
func settingsNote(keys []string) string {
	switch len(keys) {
	case 0:
		return "修改系统设置"
	case 1:
		return "修改设置项「" + keys[0] + "」"
	default:
		return "修改系统设置（" + strconv.Itoa(len(keys)) + " 项，含「" + keys[0] + "」等）"
	}
}

// batchPeerActionNote 给出批量操作的快照备注。
func batchPeerActionNote(action string, n int) string {
	label, ok := map[string]string{
		"enable":      "批量启用设备",
		"disable":     "批量停用设备",
		"delete":      "批量删除设备",
		"keepalive":   "批量修改保活间隔",
		"group":       "批量修改分组",
		"allowed_ips": "批量追加通行地址",
		"extend":      "批量延长有效期",
		"quota":       "批量修改流量额度",
	}[action]
	if !ok {
		label = "批量操作设备"
	}
	return fmt.Sprintf("%s（%d 台）", label, n)
}

// ---------------------------------------------------------------- 差异对比

// DiffItem 是一处变化。
type DiffItem struct {
	// Key 是稳定标识（连接 UUID / 设备公钥 / 域名），用于精确定位对象。
	Key string `json:"key"`
	// Name 是给人看的名字。
	Name string `json:"name"`
	// Details 是字段级差异说明；新增/删除时为空。
	Details []string `json:"details,omitempty"`
}

// DiffSection 是一类对象的三组变化。
type DiffSection struct {
	Added   []DiffItem `json:"added"`
	Removed []DiffItem `json:"removed"`
	Changed []DiffItem `json:"changed"`
}

// Count 返回该分组的变化总数。
func (d DiffSection) Count() int {
	return len(d.Added) + len(d.Removed) + len(d.Changed)
}

// SettingDiff 是一条设置项变化。
//
// 只给键名、不给取值：设置里含通知 Webhook 等凭据，而差异接口对所有登录用户开放，
// 把取值摊开等于给只读账号发凭据。知道「哪个开关被动了」已经足够定位问题。
type SettingDiff struct {
	Key string `json:"key"`
}

// SnapshotDiff 是「快照 → 当前配置」的差异。
type SnapshotDiff struct {
	SnapshotID int64         `json:"snapshot_id"`
	Filename   string        `json:"filename"`
	Note       string        `json:"note"`
	CreatedAt  time.Time     `json:"created_at"`
	Summary    string        `json:"summary"`
	Empty      bool          `json:"empty"`
	Interfaces DiffSection   `json:"interfaces"`
	Peers      DiffSection   `json:"peers"`
	DNS        DiffSection   `json:"dns"`
	Settings   []SettingDiff `json:"settings"`
}

// SnapshotDiff 计算指定快照与当前配置之间的差异，用于回滚前确认「会撤销什么」。
func (s *Service) SnapshotDiff(ctx context.Context, dir string, id int64) (*SnapshotDiff, error) {
	payload, rec, err := s.LoadBackupPayload(ctx, dir, id)
	if err != nil {
		return nil, err
	}
	current, err := s.buildBackupPayload(ctx, false)
	if err != nil {
		return nil, err
	}
	out := &SnapshotDiff{
		SnapshotID: rec.ID,
		Filename:   rec.Filename,
		Note:       rec.Note,
		CreatedAt:  rec.CreatedAt,
	}
	out.Interfaces = diffInterfaces(payload.Interfaces, current.Interfaces)
	out.Peers = diffPeers(payload.Peers, current.Peers, payload.Interfaces, current.Interfaces)
	out.DNS = diffDNS(payload.DNSRecords, current.DNSRecords)
	out.Settings = diffSettings(payload.Settings, current.Settings)
	out.Empty = out.Interfaces.Count() == 0 && out.Peers.Count() == 0 &&
		out.DNS.Count() == 0 && len(out.Settings) == 0
	out.Summary = summarizeDiff(out)
	return out, nil
}

func summarizeDiff(d *SnapshotDiff) string {
	if d.Empty {
		return "与当前配置完全一致，无需回滚"
	}
	parts := []string{}
	add := func(label string, sec DiffSection) {
		if sec.Count() == 0 {
			return
		}
		parts = append(parts, fmt.Sprintf("%s +%d -%d ~%d",
			label, len(sec.Added), len(sec.Removed), len(sec.Changed)))
	}
	add("连接", d.Interfaces)
	add("设备", d.Peers)
	add("内网域名", d.DNS)
	if len(d.Settings) > 0 {
		parts = append(parts, fmt.Sprintf("设置项 %d 处变更", len(d.Settings)))
	}
	return "回滚将撤销：" + strings.Join(parts, "；")
}

// diffInterfaces 比较两批连接。
//
// 用 UUID 而不是主键 ID 作为标识：还原/回滚会重建记录、主键全变，
// 拿 ID 比会把「同一批连接」全报成「删了又建」，差异毫无可读性。
func diffInterfaces(old, cur []model.Interface) DiffSection {
	sec := DiffSection{Added: []DiffItem{}, Removed: []DiffItem{}, Changed: []DiffItem{}}
	oldIdx := map[string]model.Interface{}
	for _, it := range old {
		oldIdx[ifaceKey(it)] = it
	}
	curIdx := map[string]model.Interface{}
	for _, it := range cur {
		curIdx[ifaceKey(it)] = it
	}
	for k, it := range oldIdx {
		c, ok := curIdx[k]
		if !ok {
			sec.Removed = append(sec.Removed, DiffItem{Key: k, Name: it.Name})
			continue
		}
		if d := compareInterface(it, c); len(d) > 0 {
			sec.Changed = append(sec.Changed, DiffItem{Key: k, Name: c.Name, Details: d})
		}
	}
	for k, it := range curIdx {
		if _, ok := oldIdx[k]; !ok {
			sec.Added = append(sec.Added, DiffItem{Key: k, Name: it.Name})
		}
	}
	sortItems(sec.Added, sec.Removed, sec.Changed)
	return sec
}

// diffPeers 比较两批设备。设备用「所属连接 + 公钥」定位：
// 公钥在连接内唯一且跨还原稳定，主键 ID 同样靠不住。
func diffPeers(old, cur []model.Peer, oldIfaces, curIfaces []model.Interface) DiffSection {
	sec := DiffSection{Added: []DiffItem{}, Removed: []DiffItem{}, Changed: []DiffItem{}}
	oldNames := ifaceNameByID(oldIfaces)
	curNames := ifaceNameByID(curIfaces)
	oldIdx := map[string]model.Peer{}
	for _, p := range old {
		oldIdx[peerKey(p, oldIfaces)] = p
	}
	curIdx := map[string]model.Peer{}
	for _, p := range cur {
		curIdx[peerKey(p, curIfaces)] = p
	}
	for k, p := range oldIdx {
		c, ok := curIdx[k]
		if !ok {
			sec.Removed = append(sec.Removed, DiffItem{Key: k, Name: peerName(p, oldNames)})
			continue
		}
		if d := comparePeer(p, c); len(d) > 0 {
			sec.Changed = append(sec.Changed, DiffItem{Key: k, Name: peerName(c, curNames), Details: d})
		}
	}
	for k, p := range curIdx {
		if _, ok := oldIdx[k]; !ok {
			sec.Added = append(sec.Added, DiffItem{Key: k, Name: peerName(p, curNames)})
		}
	}
	sortItems(sec.Added, sec.Removed, sec.Changed)
	return sec
}

func diffDNS(old, cur []store.DNSRecord) DiffSection {
	sec := DiffSection{Added: []DiffItem{}, Removed: []DiffItem{}, Changed: []DiffItem{}}
	oldIdx := map[string]store.DNSRecord{}
	for _, r := range old {
		oldIdx[store.NormalizeDNSName(r.Name)] = r
	}
	curIdx := map[string]store.DNSRecord{}
	for _, r := range cur {
		curIdx[store.NormalizeDNSName(r.Name)] = r
	}
	for k, r := range oldIdx {
		c, ok := curIdx[k]
		if !ok {
			sec.Removed = append(sec.Removed, DiffItem{Key: k, Name: r.Name})
			continue
		}
		var d []string
		d = appendField(d, "指向地址", r.IP, c.IP)
		d = appendField(d, "备注", r.Note, c.Note)
		if len(d) > 0 {
			sec.Changed = append(sec.Changed, DiffItem{Key: k, Name: c.Name, Details: d})
		}
	}
	for k, r := range curIdx {
		if _, ok := oldIdx[k]; !ok {
			sec.Added = append(sec.Added, DiffItem{Key: k, Name: r.Name})
		}
	}
	sortItems(sec.Added, sec.Removed, sec.Changed)
	return sec
}

func diffSettings(old, cur map[string]string) []SettingDiff {
	out := []SettingDiff{}
	for k, v := range cur {
		if oldV, ok := old[k]; !ok || oldV != v {
			out = append(out, SettingDiff{Key: k})
		}
	}
	for k := range old {
		if _, ok := cur[k]; !ok {
			out = append(out, SettingDiff{Key: k})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// ---------------------------------------------------------------- 标识与排序

func ifaceKey(it model.Interface) string {
	if k := strings.TrimSpace(it.UUID); k != "" {
		return k
	}
	return "name:" + it.Name
}

func ifaceNameByID(list []model.Interface) map[int64]string {
	out := make(map[int64]string, len(list))
	for _, it := range list {
		out[it.ID] = it.Name
	}
	return out
}

func ifaceKeyByID(list []model.Interface) map[int64]string {
	out := make(map[int64]string, len(list))
	for _, it := range list {
		out[it.ID] = ifaceKey(it)
	}
	return out
}

// peerKey 用「连接标识 + 公钥」定位设备；公钥缺失时退回名字（只在异常数据里出现）。
func peerKey(p model.Peer, ifaces []model.Interface) string {
	byID := ifaceKeyByID(ifaces)
	base := byID[p.InterfaceID]
	if base == "" {
		base = "iface:" + strconv.FormatInt(p.InterfaceID, 10)
	}
	pub := strings.TrimSpace(p.PublicKey)
	if pub == "" {
		pub = "name:" + p.Name
	}
	return base + "|" + pub
}

func peerName(p model.Peer, ifaceNames map[int64]string) string {
	name := strings.TrimSpace(p.Name)
	if name == "" {
		name = shortKey(strings.TrimSpace(p.PublicKey))
	}
	if in := ifaceNames[p.InterfaceID]; in != "" {
		return name + "（" + in + "）"
	}
	return name
}

func sortItems(sections ...[]DiffItem) {
	for _, s := range sections {
		sort.Slice(s, func(i, j int) bool { return s[i].Name < s[j].Name })
	}
}

// ---------------------------------------------------------------- 字段级比较

// 比较时一概跳过 Revision / CreatedAt / UpdatedAt：它们是写入行为留下的痕迹，
// 不是用户配置本身。把它们算进差异，会出现「回滚后立刻再对比，仍显示有变化」。
func compareInterface(old, cur model.Interface) []string {
	var d []string
	d = eqStr(d, "名称", old.Name, cur.Name)
	d = eqInt(d, "监听端口", old.ListenPort, cur.ListenPort)
	d = eqInt(d, "MTU", old.MTU, cur.MTU)
	d = eqInt(d, "防火墙标记", old.FWMark, cur.FWMark)
	d = eqList(d, "隧道地址", old.Addresses, cur.Addresses)
	d = eqList(d, "下发的 DNS", old.DNS, cur.DNS)
	d = eqStr(d, "DNS 模式", old.DNSMode, cur.DNSMode)
	d = eqStr(d, "路由表", old.RouteTable, cur.RouteTable)
	d = eqStr(d, "启动前脚本", old.PreUp, cur.PreUp)
	d = eqStr(d, "启动后脚本", old.PostUp, cur.PostUp)
	d = eqStr(d, "关闭前脚本", old.PreDown, cur.PreDown)
	d = eqStr(d, "关闭后脚本", old.PostDown, cur.PostDown)
	d = eqBool(d, "启用", old.Enabled, cur.Enabled)
	d = eqBool(d, "开机自启", old.Autostart, cur.Autostart)
	d = eqBool(d, "允许访问内网", old.AllowLAN, cur.AllowLAN)
	d = eqBool(d, "设备间隔离", old.IsolatePeers, cur.IsolatePeers)
	if old.PrivateKey != cur.PrivateKey {
		d = append(d, "本机密钥：已更换（密钥内容不展示）")
	}
	return d
}

func comparePeer(old, cur model.Peer) []string {
	var d []string
	d = eqStr(d, "名称", old.Name, cur.Name)
	d = eqStr(d, "上网方式", old.RouteMode, cur.RouteMode)
	d = eqList(d, "走隧道的地址", old.ClientAllowedIPs, cur.ClientAllowedIPs)
	d = eqList(d, "服务端准入地址", old.AllowedIPs, cur.AllowedIPs)
	d = eqStr(d, "对外地址", old.EndpointHost, cur.EndpointHost)
	d = eqInt(d, "对外端口", old.EndpointPort, cur.EndpointPort)
	d = eqInt(d, "保活间隔", old.Keepalive, cur.Keepalive)
	d = eqStr(d, "分组", old.GroupTag, cur.GroupTag)
	d = eqStr(d, "备注", old.Remark, cur.Remark)
	d = eqInt64(d, "流量额度（下行）", old.QuotaRx, cur.QuotaRx)
	d = eqInt64(d, "流量额度（上行）", old.QuotaTx, cur.QuotaTx)
	d = eqTimePtr(d, "到期时间", old.ExpireAt, cur.ExpireAt)
	d = eqBool(d, "启用", old.Enabled, cur.Enabled)
	if old.PresharedKey != cur.PresharedKey {
		d = append(d, "预共享密钥：已更换（密钥内容不展示）")
	}
	if old.ClientPrivateKey != cur.ClientPrivateKey {
		d = append(d, "代管客户端私钥：已更换（密钥内容不展示）")
	}
	return d
}

func appendField(d []string, label, old, new string) []string {
	if old == new {
		return d
	}
	return append(d, fmt.Sprintf("%s：%s → %s", label, orDash(old), orDash(new)))
}

func eqStr(d []string, label, old, new string) []string {
	return appendField(d, label, old, new)
}

func eqInt(d []string, label string, old, new int) []string {
	if old == new {
		return d
	}
	return append(d, fmt.Sprintf("%s：%d → %d", label, old, new))
}

func eqInt64(d []string, label string, old, new int64) []string {
	if old == new {
		return d
	}
	return append(d, fmt.Sprintf("%s：%d → %d", label, old, new))
}

func eqBool(d []string, label string, old, new bool) []string {
	if old == new {
		return d
	}
	return append(d, fmt.Sprintf("%s：%s → %s", label, onOff(old), onOff(new)))
}

func eqTimePtr(d []string, label string, old, new *time.Time) []string {
	oldS, newS := "-", "-"
	if old != nil {
		oldS = old.Format("2006-01-02 15:04")
	}
	if new != nil {
		newS = new.Format("2006-01-02 15:04")
	}
	if oldS == newS {
		return d
	}
	return append(d, fmt.Sprintf("%s：%s → %s", label, oldS, newS))
}

// eqList 比较地址这类列表，忽略顺序：["10.0.0.1/24","fd00::1/64"] 与
// ["fd00::1/64","10.0.0.1/24"] 是同一份配置，顺序不同不该报成变更。
func eqList(d []string, label string, old, new []string) []string {
	if sameList(old, new) {
		return d
	}
	return append(d, fmt.Sprintf("%s：[%s] → [%s]",
		label, strings.Join(old, ", "), strings.Join(new, ", ")))
}

// sameList 判断两个列表是否等价（忽略顺序，空列表与空列表等价）。
//
// 不复用 peer.go 里的 sameStringSet：那个函数把「两边都为空」判为不等，
// 因为它的用途是「两台设备的通行地址是否完全相同」，空地址不该算冲突；
// 而差异对比里「原本没有地址、现在也没有」正是一致。
func sameList(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	count := map[string]int{}
	for _, v := range a {
		count[v]++
	}
	for _, v := range b {
		count[v]--
		if count[v] < 0 {
			return false
		}
	}
	return true
}

func orDash(v string) string {
	if strings.TrimSpace(v) == "" {
		return "（空）"
	}
	return v
}

func onOff(v bool) string {
	if v {
		return "开"
	}
	return "关"
}

// ---------------------------------------------------------------- 回滚

// CreateSnapshot 手动留一份配置快照。
//
// 返回 (nil, nil) 表示当前配置与最近一份快照完全一致，没有重复留档。
func (s *Service) CreateSnapshot(ctx context.Context, note string, a Actor) (*store.BackupRecord, error) {
	note = strings.TrimSpace(note)
	if note == "" {
		note = "手动留档"
	}
	rec, err := s.takeSnapshot(ctx, "snapshot.manual", note)
	if err != nil {
		return nil, err
	}
	if rec != nil {
		s.audit(ctx, a, "snapshot.create", "snapshot", fmt.Sprint(rec.ID), "", "", "ok", note)
	}
	return rec, nil
}

// RollbackSnapshot 一键回滚：把当前配置整体恢复到指定快照的状态。
//
// 语义上等价于「只回滚配置的一次还原」：
//   - 覆盖连接、设备、内网域名与设置项；
//   - 不动账号——不回退密码与二次验证，否则回滚会变成安全倒退；
//   - 回滚前先为当前状态留一份快照，滚错了还能再滚回来；
//   - 回滚成功后立即触发一次幂等收敛，让内核态与数据库同进退（R7）。
//
// 收敛失败时返回明确错误而不静默：此时数据库已是快照态、内核还是旧态，
// 用户必须知道这一点，才能决定是重试还是再次回滚。
func (s *Service) RollbackSnapshot(ctx context.Context, dir string, id int64, a Actor) (int, error) {
	payload, target, err := s.LoadBackupPayload(ctx, dir, id)
	if err != nil {
		return 0, err
	}
	if target.Kind != store.BackupKindAuto {
		return 0, fmt.Errorf("这条记录不是配置快照，请到「备份还原」里操作")
	}
	if len(payload.Interfaces) == 0 {
		// 快照里一条连接都没有，多半是文件损坏或被清空。
		// 照单全收会把用户的整套配置删光，宁可不做。
		return 0, fmt.Errorf("快照里没有任何连接，已拒绝回滚以免清空现有配置")
	}
	if _, err := s.takeSnapshot(ctx, "snapshot.pre_rollback",
		"回滚前自动存档（即将回滚到 "+target.Filename+"）"); err != nil && !errors.Is(err, errSnapshotDirMissing) {
		// 不阻断回滚：用户要的是回到过去，而不是「因为存档失败所以回不去」。
		_ = s.Store.AddLog(ctx, "warn", "snapshot",
			"回滚前的自动存档失败，回滚后将无法一键回到回滚前的状态", err.Error())
	}
	n, err := s.applyBackupPayload(ctx, payload, false)
	if err != nil {
		s.audit(ctx, a, "snapshot.rollback", "snapshot", fmt.Sprint(id), "", "", "error", err.Error())
		return n, err
	}
	if err := s.reconcile(ctx); err != nil {
		s.audit(ctx, a, "snapshot.rollback", "snapshot", fmt.Sprint(id), "", fmt.Sprint(n),
			"error", "配置已回滚但下发失败："+err.Error())
		return n, fmt.Errorf("配置数据已回滚，但下发到内核失败：%w。快照仍保留，可点「重新应用配置」重试", err)
	}
	s.audit(ctx, a, "snapshot.rollback", "snapshot", fmt.Sprint(id), "", fmt.Sprint(n), "ok", target.Filename)
	return n, nil
}
