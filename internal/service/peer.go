// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package service

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"fnwg/internal/model"
	"fnwg/internal/wgback"
	"fnwg/internal/wgconf"
	"fnwg/internal/wgkey"
	"sync"
)

// ListPeers 返回节点列表（interfaceID<=0 表示全部）。敏感字段默认不下发。
func (s *Service) ListPeers(ctx context.Context, interfaceID int64) ([]model.Peer, error) {
	peers, err := s.Store.ListPeers(ctx, interfaceID)
	if err != nil {
		return nil, err
	}
	s.Cache.EnrichPeers(peers)
	s.markConfigStale(ctx, peers)
	markSitePeers(peers)
	for i := range peers {
		peers[i].PresharedKey = ""
		peers[i].ClientPrivateKey = ""
	}
	return peers, nil
}

// GetPeer 返回单个节点。
func (s *Service) GetPeer(ctx context.Context, id int64) (*model.Peer, error) {
	p, err := s.Store.GetPeer(ctx, id)
	if err != nil {
		return nil, err
	}
	list := []model.Peer{*p}
	s.Cache.EnrichPeers(list)
	s.markConfigStale(ctx, list)
	markSitePeers(list)
	*p = list[0]
	p.PresharedKey = ""
	p.ClientPrivateKey = ""
	return p, nil
}

// PeerInput 是节点新增/编辑入参。
type PeerInput struct {
	InterfaceID      int64    `json:"interface_id"`
	Name             string   `json:"name"`
	PublicKey        string   `json:"public_key"`
	PresharedKey     string   `json:"preshared_key"`
	ClientPrivateKey string   `json:"client_private_key"`
	RouteMode        string   `json:"route_mode"`
	ClientAllowedIPs []string `json:"client_allowed_ips"`
	EndpointHost     string   `json:"endpoint_host"`
	EndpointPort     int      `json:"endpoint_port"`
	AllowedIPs       []string `json:"allowed_ips"`
	// LANPolicy / LANTargets 是「这台设备能访问内网的哪些目标」（见 model.Peer.LANPolicy）。
	// 它们落在服务端的转发规则上，设备侧改不了 —— 与设备侧的通行范围是两件事。
	LANPolicy  string     `json:"lan_policy"`
	LANTargets []string   `json:"lan_targets"`
	Keepalive  int        `json:"persistent_keepalive"`
	GroupTag   string     `json:"group_tag"`
	Remark     string     `json:"remark"`
	QuotaRx    int64      `json:"quota_rx"`
	QuotaTx    int64      `json:"quota_tx"`
	ExpireAt   *time.Time `json:"expire_at"`
	// Enabled 用指针表达「有没有指定」：新建时为 nil 表示按默认（不启用），编辑时为 nil 表示保持原值。
	// 与连接的入参同理：非指针布尔会让部分更新静默把设备停用。
	Enabled *bool `json:"enabled"`
	// GenerateKeys 为 true 时自动生成密钥对并托管私钥。
	GenerateKeys bool `json:"generate_keys"`
	// GeneratePSK 为 true 时生成预共享密钥。
	GeneratePSK bool `json:"generate_psk"`
	// AutoAddress 为 true 时自动分配隧道地址。
	AutoAddress bool `json:"auto_address"`
}

// CreatePeer 新增节点。
func (s *Service) CreatePeer(ctx context.Context, in PeerInput, a Actor) (*model.Peer, error) {
	note := "新增设备"
	if n := strings.TrimSpace(in.Name); n != "" {
		note += "「" + n + "」"
	}
	s.snapshotBefore(ctx, "peer.create", note)
	p, err := s.createPeer(ctx, in, a)
	if err != nil {
		return nil, err
	}
	_ = s.reconcile(ctx)
	return p, nil
}

// createPeer 落库一台设备，但**不触发收敛**。
//
// 单台创建走 CreatePeer（落库后立即收敛）。批量导入则逐条调用本函数、
// 最后统一收敛一次：否则 100 台设备会触发 100 次全量收敛，既慢又会把
// 收敛循环搅乱（这正是 V6「导入 100 台 ≤ 10 秒」能否达成的关键）。
func (s *Service) createPeer(ctx context.Context, in PeerInput, a Actor) (*model.Peer, error) {
	it, err := s.Store.GetInterface(ctx, in.InterfaceID)
	if err != nil {
		return nil, fmt.Errorf("所选连接不存在，请刷新页面后重试")
	}
	if in.RouteMode == "" {
		in.RouteMode = model.RouteModeLAN
	}
	policy, lanTargets, err := normalizePeerLANAccess(in.LANPolicy, in.LANTargets)
	if err != nil {
		return nil, err
	}
	p := &model.Peer{
		InterfaceID:      in.InterfaceID,
		Name:             strings.TrimSpace(in.Name),
		PublicKey:        strings.TrimSpace(in.PublicKey),
		PresharedKey:     strings.TrimSpace(in.PresharedKey),
		RouteMode:        in.RouteMode,
		ClientAllowedIPs: in.ClientAllowedIPs,
		EndpointHost:     strings.TrimSpace(in.EndpointHost),
		EndpointPort:     in.EndpointPort,
		AllowedIPs:       in.AllowedIPs,
		LANPolicy:        policy,
		LANTargets:       lanTargets,
		Keepalive:        in.Keepalive,
		GroupTag:         in.GroupTag,
		Remark:           in.Remark,
		QuotaRx:          in.QuotaRx,
		QuotaTx:          in.QuotaTx,
		ExpireAt:         in.ExpireAt,
		Enabled:          in.Enabled != nil && *in.Enabled,
	}

	if in.GenerateKeys || p.PublicKey == "" {
		priv, pub, err := wgkey.Generate()
		if err != nil {
			return nil, err
		}
		p.ClientPrivateKey, p.PublicKey = priv, pub
	} else if !wgkey.Validate(p.PublicKey) {
		return nil, fmt.Errorf("对方设备的识别码格式不正确：应为一串 44 个字符的编码，请确认完整复制")
	}
	if in.GeneratePSK || (p.PresharedKey == "" && in.GenerateKeys) {
		psk, err := wgkey.GeneratePSK()
		if err != nil {
			return nil, err
		}
		p.PresharedKey = psk
	} else if p.PresharedKey != "" && !wgkey.Validate(p.PresharedKey) {
		return nil, fmt.Errorf("二次加密口令格式不正确，请重新生成或清空该项")
	}

	if p.Name == "" {
		p.Name = "设备-" + shortKey(p.PublicKey)
	}
	if in.AutoAddress || len(p.AllowedIPs) == 0 {
		existing, err := s.Store.ListPeers(ctx, it.ID)
		if err != nil {
			return nil, err
		}
		// 手填了 IPv4 就不再自动追加一个。
		//
		// 界面恒传 auto_address=true（它的含义是「允许自动分配」），而这里原先只要这个标志
		// 为真就追加 —— 于是用户手填 `10.20.0.10/32` 之后，设备身上还挂着自动挑的
		// `10.20.0.3/32`。"我把它改成不重复的地址了"就是这么失效的：多出来的那个地址照样
		// 与对端的设备撞车，而界面上完全看不出来（真机踩到过：日志里一台设备的准入地址里
		// 同时有 10.206.0.10/32 与 10.206.0.3/32）。
		if !hasIPv4Addr(p.AllowedIPs) {
			// 手填的那一项也要算作「已占用」，否则自动分配可能挑到同一个地址。
			used := existing
			if len(p.AllowedIPs) > 0 {
				used = append([]model.Peer{{AllowedIPs: p.AllowedIPs}}, existing...)
			}
			if ip := nextFreeIP(it, used); ip != "" {
				p.AllowedIPs = append(p.AllowedIPs, ip)
			}
		}
	}
	if p.Keepalive == 0 && p.EndpointHost == "" {
		p.Keepalive = 25
	}
	if err := s.validatePeer(ctx, p, 0); err != nil {
		return nil, err
	}
	if err := s.Store.CreatePeer(ctx, p); err != nil {
		return nil, err
	}
	p.InterfaceName = it.Name
	s.audit(ctx, a, "peer.create", "peer", fmt.Sprint(p.ID), "", p.Name, "ok", "")
	return p, nil
}

// PeerImportRow 是批量导入里的一台设备。
type PeerImportRow struct {
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
	Remark    string `json:"remark"`
	GroupTag  string `json:"group_tag"`
}

// PeerImportItem 是单台设备的导入结果（逐条回传成功或失败原因）。
type PeerImportItem struct {
	Index  int    `json:"index"`
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
	PeerID int64  `json:"peer_id,omitempty"`
}

// PeerImportResult 是批量导入汇总。
type PeerImportResult struct {
	Created int              `json:"created"`
	Failed  int              `json:"failed"`
	Items   []PeerImportItem `json:"items"`
}

// ImportPeers 批量创建设备：逐条创建并汇总结果，最后统一收敛一次。
//
// 与「一次导入整份 wg-quick 配置」不同：这里导入的是**已有的连接下的多台设备**，
// 且必须逐条给出成功/失败明细 —— 重复识别码、格式非法等问题要能定位到具体哪一行，
// 否则用户面对一堆设备根本不知道该改哪一台。
func (s *Service) ImportPeers(ctx context.Context, ifaceID int64, rows []PeerImportRow, a Actor) (*PeerImportResult, error) {
	if len(rows) == 0 {
		return nil, fmt.Errorf("没有可导入的设备")
	}
	if len(rows) > 500 {
		return nil, fmt.Errorf("单次最多导入 500 台设备，当前 %d 台，请分批导入", len(rows))
	}
	if _, err := s.Store.GetInterface(ctx, ifaceID); err != nil {
		return nil, fmt.Errorf("所选连接不存在，请刷新页面后重试")
	}
	// 整批只留一份快照：循环里每台都留一次，500 台的导入会生成 500 份全量文件。
	s.snapshotBefore(ctx, "peer.import", fmt.Sprintf("批量导入设备（%d 台）", len(rows)))
	res := &PeerImportResult{Items: make([]PeerImportItem, 0, len(rows))}
	for i, r := range rows {
		name := strings.TrimSpace(r.Name)
		item := PeerImportItem{Index: i, Name: name}
		if name == "" {
			item.Error = "缺少设备名称"
			res.Failed++
			res.Items = append(res.Items, item)
			continue
		}
		pub := strings.TrimSpace(r.PublicKey)
		p, err := s.createPeer(ctx, PeerInput{
			InterfaceID: ifaceID,
			Name:        name,
			PublicKey:   pub,
			Remark:      strings.TrimSpace(r.Remark),
			GroupTag:    strings.TrimSpace(r.GroupTag),
			Keepalive:   25,
			Enabled:     boolPtr(true),
			AutoAddress: true,
			// 没给识别码的就自动生成密钥对（等同于在界面点「自动生成」）
			GenerateKeys: pub == "",
			GeneratePSK:  true,
		}, a)
		if err != nil {
			item.Error = err.Error()
			res.Failed++
		} else {
			item.OK = true
			item.PeerID = p.ID
			item.Name = p.Name
			res.Created++
		}
		res.Items = append(res.Items, item)
	}
	if res.Created > 0 {
		_ = s.reconcile(ctx)
	}
	s.audit(ctx, a, "peer.import", "peer", fmt.Sprint(ifaceID), "",
		fmt.Sprintf("成功 %d / 失败 %d", res.Created, res.Failed), "ok", "")
	return res, nil
}

// UpdatePeer 更新节点。
func (s *Service) UpdatePeer(ctx context.Context, id int64, in PeerInput, a Actor) (*model.Peer, error) {
	p, err := s.Store.GetPeer(ctx, id)
	if err != nil {
		return nil, err
	}
	if in.InterfaceID > 0 {
		p.InterfaceID = in.InterfaceID
	}
	p.Name = strings.TrimSpace(in.Name)
	if in.PublicKey != "" {
		if !wgkey.Validate(in.PublicKey) {
			return nil, fmt.Errorf("对方设备的识别码格式不正确：应为一串 44 个字符的编码")
		}
		p.PublicKey = in.PublicKey
	}
	p.RouteMode = in.RouteMode
	p.ClientAllowedIPs = in.ClientAllowedIPs
	p.EndpointHost = strings.TrimSpace(in.EndpointHost)
	p.EndpointPort = in.EndpointPort
	p.AllowedIPs = in.AllowedIPs
	policy, lanTargets, err := normalizePeerLANAccess(in.LANPolicy, in.LANTargets)
	if err != nil {
		return nil, err
	}
	p.LANPolicy, p.LANTargets = policy, lanTargets
	p.Keepalive = in.Keepalive
	p.GroupTag = in.GroupTag
	p.Remark = in.Remark
	p.QuotaRx, p.QuotaTx = in.QuotaRx, in.QuotaTx
	p.ExpireAt = in.ExpireAt
	// 只有显式给出才改动（理由见 PeerInput.Enabled 的说明）。
	if in.Enabled != nil {
		// 用户显式启停时清掉「自动停用原因」。
		//
		// 两个方向都必要：手工停用的设备必须与「因额度停用」区分开，否则月初的自动恢复
		// 会把它悄悄放开；手工启用的设备也不该留着一个已经不成立的原因。
		// 真因额度用尽被停用时，引擎会重新把原因写上。
		p.Enabled = *in.Enabled
		p.DisabledReason = ""
	}
	if in.GenerateKeys {
		priv, pub, err := wgkey.Generate()
		if err != nil {
			return nil, err
		}
		p.ClientPrivateKey, p.PublicKey = priv, pub
	} else if in.ClientPrivateKey != "" {
		p.ClientPrivateKey = in.ClientPrivateKey
	}
	// 二次加密口令的三个来源，别混：
	//   - GeneratePSK=true：用户明确点了「生成新口令」；
	//   - PresharedKey 非空：调用方明确给出（轮换或外部录入）；
	//   - 两者都为空：**保持原值**，这不是「清空」。
	//
	// 第三条修的是一处会静默损坏数据的缺陷：设备编辑抽屉（frontend 的 Peers.vue）根本不提交
	// preshared_key 字段，而这里**原先无条件用空值覆盖** —— 于是「编辑设备改个名字或换个地址」
	// 就会把它的二次加密口令清空；设备手上那份配置还带着旧口令，握手被对端直接拒绝，现象只是
	// 「一直离线」，成因（口令被清掉）在界面上完全看不出来。真机日志里能读出来：
	//
	//	更新节点 MAC（…）（通行范围、清除二次加密口令）
	//
	// 将来若确实需要「清除口令」这个能力，请另加一个显式开关，不要再用「空值 = 清空」——
	// 那正是这次故障的根源。
	if in.GeneratePSK {
		psk, err := wgkey.GeneratePSK()
		if err != nil {
			return nil, err
		}
		p.PresharedKey = psk
	} else if v := strings.TrimSpace(in.PresharedKey); v != "" {
		p.PresharedKey = v
	}
	if err := s.validatePeer(ctx, p, id); err != nil {
		return nil, err
	}
	s.snapshotBefore(ctx, "peer.update", "修改设备「"+p.Name+"」")
	if err := s.Store.UpdatePeer(ctx, p); err != nil {
		return nil, err
	}
	s.audit(ctx, a, "peer.update", "peer", fmt.Sprint(id), "", p.Name, "ok", "")
	_ = s.reconcile(ctx)
	p.PresharedKey = ""
	p.ClientPrivateKey = ""
	return p, nil
}

// DeletePeer 删除节点。
func (s *Service) DeletePeer(ctx context.Context, id int64, a Actor) error {
	p, err := s.Store.GetPeer(ctx, id)
	if err != nil {
		return err
	}
	s.snapshotBefore(ctx, "peer.delete", "删除设备「"+p.Name+"」")
	if err := s.Store.DeletePeer(ctx, id); err != nil {
		return err
	}
	s.audit(ctx, a, "peer.delete", "peer", fmt.Sprint(id), p.Name, "", "ok", "")
	return s.reconcile(ctx)
}

// BatchPeerRequest 是批量操作请求。
type BatchPeerRequest struct {
	IDs        []int64  `json:"ids"`
	Action     string   `json:"action"`
	Keepalive  int      `json:"persistent_keepalive"`
	AllowedIPs []string `json:"allowed_ips"`
	GroupTag   string   `json:"group_tag"`
	ExtendDays int      `json:"extend_days"`
	QuotaRx    int64    `json:"quota_rx"`
	QuotaTx    int64    `json:"quota_tx"`
}

// BatchPeers 执行批量操作。
func (s *Service) BatchPeers(ctx context.Context, req BatchPeerRequest, a Actor) (string, error) {
	if len(req.IDs) == 0 {
		return "", fmt.Errorf("请先勾选要操作的设备")
	}
	s.snapshotBefore(ctx, "peer.batch_"+req.Action, batchPeerActionNote(req.Action, len(req.IDs)))
	switch req.Action {
	case "enable", "disable":
		n, err := s.Store.BatchSetPeerEnabled(ctx, req.IDs, req.Action == "enable")
		if err != nil {
			return "", err
		}
		s.audit(ctx, a, "peer.batch_"+req.Action, "peer", idsString(req.IDs), "", fmt.Sprint(n), "ok", "")
		_ = s.reconcile(ctx)
		return fmt.Sprintf("已%s %d 个节点", map[bool]string{true: "启用", false: "禁用"}[req.Action == "enable"], n), nil

	case "delete":
		n, err := s.Store.BatchDeletePeers(ctx, req.IDs)
		if err != nil {
			return "", err
		}
		s.audit(ctx, a, "peer.batch_delete", "peer", idsString(req.IDs), "", fmt.Sprint(n), "ok", "")
		_ = s.reconcile(ctx)
		return fmt.Sprintf("已删除 %d 个节点", n), nil
	}

	// 其余动作逐条更新
	changed := 0
	for _, id := range req.IDs {
		p, err := s.Store.GetPeer(ctx, id)
		if err != nil {
			continue
		}
		switch req.Action {
		case "keepalive":
			p.Keepalive = req.Keepalive
		case "group":
			p.GroupTag = req.GroupTag
		case "allowed_ips":
			if err := validateCIDRList("允许通行的地址", req.AllowedIPs); err != nil {
				return "", err
			}
			p.AllowedIPs = wgconf.MergeCIDRs(append(p.AllowedIPs, req.AllowedIPs...))
		case "extend":
			base := time.Now()
			if p.ExpireAt != nil && p.ExpireAt.After(base) {
				base = *p.ExpireAt
			}
			t := base.AddDate(0, 0, req.ExtendDays)
			p.ExpireAt = &t
		case "quota":
			p.QuotaRx, p.QuotaTx = req.QuotaRx, req.QuotaTx
		default:
			return "", fmt.Errorf("不支持的操作类型：%s", req.Action)
		}
		if err := s.Store.UpdatePeer(ctx, p); err != nil {
			continue
		}
		changed++
	}
	s.audit(ctx, a, "peer.batch_"+req.Action, "peer", idsString(req.IDs), "", fmt.Sprint(changed), "ok", "")
	_ = s.reconcile(ctx)
	return fmt.Sprintf("已更新 %d 个节点", changed), nil
}

// PeerConfigResult 是客户端配置下发结果。
type PeerConfigResult struct {
	Conf            string   `json:"conf"`
	Filename        string   `json:"filename"`
	Endpoint        string   `json:"endpoint"`
	ServerPublicKey string   `json:"server_public_key"`
	ClientAddress   []string `json:"client_address"`
	AllowedIPs      []string `json:"allowed_ips"`
	QRPayload       string   `json:"qr_payload"`
	Warning         string   `json:"warning,omitempty"`
}

// PeerConfig 生成客户端可直接导入的配置（同时用于二维码内容）。
func (s *Service) PeerConfig(ctx context.Context, id int64) (*PeerConfigResult, error) {
	p, err := s.Store.GetPeer(ctx, id)
	if err != nil {
		return nil, err
	}
	it, err := s.Store.GetInterface(ctx, p.InterfaceID)
	if err != nil {
		return nil, err
	}
	if p.ClientPrivateKey == "" {
		return nil, fmt.Errorf("这台设备没有保存密钥（当初是以外部识别码添加的），因此无法生成二维码。请在「编辑」中勾选「保存时生成新的密钥对」后重试")
	}
	serverPub, err := wgkey.PublicKey(it.PrivateKey)
	if err != nil {
		return nil, err
	}
	endpoint, warn := s.serverEndpoint(ctx, it)
	// 端口对不上时把结论直接带进二维码页面：用户正是在这一步复制地址、转发配置，
	// 那一刻不说，他就只能等「怎么都连不上」再回来猜（列表里那行提示未必会再被看一眼）。
	if note := s.portNoteFor(ctx, *it); note != "" {
		if warn != "" {
			warn += "；"
		}
		warn += note
	}
	// 站点互联的对端条目不是「一台设备」：它代表的就是**对面那台 NAS**，
	// 生成的配置里带着对端连接的私钥与隧道地址。
	//
	// 把它当普通设备配置拿到另一台机器上用，那台机器会以对端身份连上来、把对端
	// NAS 顶掉（同一个公钥在同一时刻只对应一个有效端点），现象是「两台 NAS
	// 时通时不通、设备访问不了对端内网」，且两端界面都看不出异常。
	if isSitePeer(p) {
		msg := "这条配置是给「对端 NAS」用的（含对端连接的私钥与隧道地址）：请用它配置对面那台 NAS，" +
			"不要用在你自己的手机或电脑上 —— 否则那台设备会冒充对端 NAS，双方互相抢占连接。"
		if warn != "" {
			warn += "；"
		}
		warn += msg
	}
	// 设备的登记地址全落在隧道之外：配置照常生成、二维码看起来完全正常，设备却怎么都连不上
	//（回包无路可走）。最常见的是「为了避开两台 NAS 撞车改了连接网段，而旧设备地址没跟着改」——
	// 那句话只在二维码这一步说得出，用户也就只有在这一步才可能看到（见 access.go 的同一判据）。
	if peerAddrsOutsideTunnel(it, p) {
		msg := fmt.Sprintf("这台设备的地址（%s）不在本连接的隧道网段 %s 内：它的配置里会带一个隧道外的地址，"+
			"握手能成、回包却没有路可走，现象只是「怎么都连不上」。请到「我的设备」把它改成隧道网段内的地址",
			strings.Join(p.AllowedIPs, "、"), strings.Join(cidrStrings(it.Addresses), "、"))
		if warn != "" {
			warn += "；"
		}
		warn += msg
	}
	// 设备拿到的 DNS 会是本机隧道地址时，必须说清「它只在连接期间可用」。
	//
	// 那个地址只有在隧道建立后才存在：断开后如果客户端没把 DNS 还原（直接退出客户端、
	// 睡眠、崩溃、切 Wi-Fi 都会留下这种状态），设备上的域名解析会全部失败 ——
	// 现象是「所有按域名访问的都不通」，而 FN Connect 这类正是按域名访问的功能。
	// 用户完全想不到与这条连接有关（真机反馈过）。这一步服务端无法代劳，只能提前提醒。
	if s.dnsResolveOn(ctx) {
		if host := firstIPv4Host(it.Addresses); host != "" && containsString(s.clientDNS(ctx, it), host) {
			if warn != "" {
				warn += "；"
			}
			warn += fmt.Sprintf("这台设备的 DNS 会被指向本机隧道地址 %s，它「只在连接建立期间可用」："+
				"断开连接后如果这台设备上不了网（尤其是访问按域名访问的服务），"+
				"请把它网卡上的 DNS 改回「自动获取」—— 客户端异常退出时可能没把 DNS 还原，服务端无法代劳", host)
		}
	}
	clientAddrs, extraRoutes := wgconf.SplitClientAndServerIPs(it, p)
	clientAllowed := s.clientAllowedIPs(ctx, it, p, extraRoutes)
	conf := wgconf.RenderClient(serverPub, p, wgconf.RenderClientOptions{
		Endpoint:         endpoint,
		ClientPrivateKey: p.ClientPrivateKey,
		ClientAddress:    clientAddrs,
		AllowedIPs:       clientAllowed,
		DNS:              s.clientDNS(ctx, it),
		MTU:              it.MTU,
		Keepalive:        p.Keepalive,
	})
	// 记下「这台设备刚拿到的配置」：之后改动对外地址、DNS、通行范围时，
	// 界面就能据此标出「配置已过期，需要重新扫码」，而不是让用户自己猜。
	s.rememberPeerConfig(ctx, p, wgconf.ClientFingerprint(wgconf.ClientConfigInputs{
		Endpoint:    endpoint,
		ClientAddrs: clientAddrs,
		AllowedIPs:  clientAllowed,
		DNS:         s.clientDNS(ctx, it),
		MTU:         it.MTU,
		Keepalive:   p.Keepalive,
		ServerPub:   serverPub,
	}))
	name := p.Name
	if name == "" {
		name = fmt.Sprintf("peer-%d", p.ID)
	}
	return &PeerConfigResult{
		Conf:            conf,
		Filename:        name + ".conf",
		Endpoint:        endpoint,
		ServerPublicKey: serverPub,
		ClientAddress:   clientAddrs,
		AllowedIPs:      clientAllowed,
		QRPayload:       conf,
		Warning:         warn,
	}, nil
}

// clientDNS 返回下发给设备的 DNS 服务器地址。三种情况，按优先级：
//
//  1. 打开「内网域名解析」时下发**本连接的隧道地址**：设备必须把 NAS 当作解析器，
//     否则它解析不了家里设备名。这是用户显式打开的另一个开关，优先级高于连接的
//     「下发 DNS」—— 否则「不下发」会让这个功能静默失效，而界面上看不出原因。
//  2. 「下发 DNS = 不下发」时不下发任何 DNS。连接里那一栏仍作为本应用解析器的上游
//     （见 reconcile.syncDNS 的上游取法），只是不推给设备。
//  3. 其余情况下发连接里配置的 DNS（与升级前行为一致）。
func (s *Service) clientDNS(ctx context.Context, it *model.Interface) []string {
	if s.dnsResolveOn(ctx) {
		if host := firstIPv4Host(it.Addresses); host != "" {
			return []string{host}
		}
		// 没有可用的 IPv4 隧道地址时退回原值：宁可不生效，也不要下发一个设备连不上的地址
		return it.DNS
	}
	if it.DNSMode == model.DNSModeOff {
		return nil
	}
	return it.DNS
}

// dnsResolveOn 判断「内网域名解析」总开关是否打开。
//
// 它同时决定「下发给设备的 DNS」与「本机是否起解析服务」，两处必须同源：
// 各写一遍字面量迟早会出现「设备被指向本机、本机却没起解析服务」。
func (s *Service) dnsResolveOn(ctx context.Context) bool {
	return s.Store.GetSetting(ctx, model.SettingDNSResolve, "") == "1"
}

// firstIPv4Host 返回地址清单里第一个 IPv4 地址（去掉掩码）；没有则返回空串。
func firstIPv4Host(addrs []string) string {
	for _, a := range addrs {
		if ip, _, err := net.ParseCIDR(strings.TrimSpace(a)); err == nil && ip.To4() != nil {
			return ip.String()
		}
	}
	return ""
}

// clientAllowedIPs 生成客户端侧的通行范围（决定设备上哪些流量走隧道）。
//
// 这是「设备上网方式」的落地：只影响设备自身的配置，绝不改动 NAS 的路由。
func (s *Service) clientAllowedIPs(ctx context.Context, it *model.Interface, p *model.Peer, extra []string) []string {
	switch p.RouteMode {
	case model.RouteModeFull:
		return []string{"0.0.0.0/0", "::/0"}
	case model.RouteModeCustom:
		if len(p.ClientAllowedIPs) > 0 {
			return wgconf.MergeCIDRs(p.ClientAllowedIPs)
		}
	}
	// lan（默认）：仅让设备能访问本端内网、对端站点内网与额外放行的网段
	out := append([]string{}, s.homeLANSubnets(ctx)...)
	out = append(out, extra...)
	// 站点互联（异地组网）：把对端内网也并入设备通行范围。
	//
	// 少了这一项，现象是「隧道通了、能访问本机内网，却访问不了另一台 NAS 后面的机器」——
	// 而且不报错：设备根本没把发往对端内网的包送进隧道。
	// 与「设备上网方式=全量」的区别是：这里只多放行对端内网，上网流量仍走设备本地网络。
	out = append(out, s.siteLANSubnets(ctx)...)
	if len(out) == 0 {
		// 探测失败时退化为"只能访问隧道内地址"，仍然可用且安全
		out = append(out, it.Addresses...)
	}
	return wgconf.MergeCIDRs(out)
}

// siteLANSubnets 收集本机全部「站点互联」对端的内网网段（隧道之外的那些）。
//
// 判定复用 topology.siteSubnetsOf：某条链路里「准入地址落在本连接隧道之外」的部分
// 就是对端内网。三处（拓扑展示、数据面转发来源、这里）共用同一套推导，
// 避免出现「拓扑画了、配置却不认」这种自相矛盾。
func (s *Service) siteLANSubnets(ctx context.Context) []string {
	ifaces, err := s.Store.ListInterfaces(ctx)
	if err != nil {
		return nil
	}
	out := []string{}
	for i := range ifaces {
		it := &ifaces[i]
		if !it.Enabled {
			continue
		}
		peers, err := s.Store.ListPeers(ctx, it.ID)
		if err != nil {
			continue
		}
		for j := range peers {
			if !peers[j].Enabled {
				continue
			}
			out = append(out, siteSubnetsOf(it, &peers[j])...)
		}
	}
	return wgconf.MergeCIDRs(out)
}

// homeLANSubnets 本端局域网网段：优先使用设置中的值，否则自动探测。
func (s *Service) homeLANSubnets(ctx context.Context) []string {
	if v := s.Store.GetSetting(ctx, "home_lan_cidrs", ""); v != "" {
		return wgconf.MergeCIDRs(strings.Split(v, ","))
	}
	return detectLocalSubnets()
}

// RevealPeerSecrets 回显节点密钥（需 key.reveal 权限）。
func (s *Service) RevealPeerSecrets(ctx context.Context, id int64, a Actor) (map[string]string, error) {
	p, err := s.Store.GetPeer(ctx, id)
	if err != nil {
		return nil, err
	}
	s.audit(ctx, a, "peer.reveal_key", "peer", fmt.Sprint(id), "", "", "ok", "查看节点密钥")
	out := map[string]string{"public_key": p.PublicKey}
	if p.ClientPrivateKey != "" {
		out["client_private_key"] = p.ClientPrivateKey
	}
	if p.PresharedKey != "" {
		out["preshared_key"] = p.PresharedKey
	}
	return out, nil
}

// serverEndpoint 解析服务端对外地址。
// 自动探测到的本机地址要做缓存。
//
// 为什么必须缓存：这个地址会进「设备配置指纹」的比对（见 baselineFor / peerConfigFingerprint）。
// 若每次请求都重新探测，多网卡机器（家里的 NAS 很常见：eth0 与 docker0 / 网桥并存）可能这次选到这张、
// 下次选到那张，指纹就跟着变 —— 表现是设备列表里「需重新扫码」怎么重新导入都清不掉（用户实际遇到过）。
// 缓存期内指纹必然一致；地址真的变了（超过缓存期）仍会被识别为需要重新导入，这正是该标记的用途。
var localIPv4Cache struct {
	sync.Mutex
	at  time.Time
	val string
}

const localIPv4TTL = 10 * time.Minute

func cachedLocalIPv4() string {
	localIPv4Cache.Lock()
	defer localIPv4Cache.Unlock()
	if !localIPv4Cache.at.IsZero() && time.Since(localIPv4Cache.at) < localIPv4TTL {
		return localIPv4Cache.val
	}
	v := detectLocalIPv4()
	localIPv4Cache.at, localIPv4Cache.val = time.Now(), v
	return v
}

// serverEndpoint 解析「这台设备/这个对端该连到哪个地址」，供二维码、邀请与配置指纹共用。
//
// 端口策略（多连接）：
//   - 设置里只写了主机名/IP（不带端口）→ 按**本连接**的 ListenPort 拼接。
//     这样每条连接各有各的外部端口（同号映射，路由器上放行哪个就通哪条），多连接才能同时对外。
//   - 设置里写了端口 → 原样使用（兼容既有配置）。一个外部端口同一时刻只能转给一条连接，
//     所以此时只有监听该端口的那条连接能从外网回来，其余由 portNoteFor 常驻提示。
//
// 为什么不能一律用设置值：此前就是这么做的，于是第二条连接监听 51821 时，
// 它的二维码里仍写 51820 —— 握手包落到 wg0 上、公钥对不上，现象只有「一直连不上」，
// 状态与日志里都看不出与端口有关（真机踩到过）。
func (s *Service) serverEndpoint(ctx context.Context, it *model.Interface) (string, string) {
	if v := s.Store.GetSetting(ctx, "server_endpoint", ""); v != "" {
		return endpointForInterface(v, it.ListenPort), ""
	}
	ip := cachedLocalIPv4()
	if ip == "" {
		return "", "尚未配置「服务端对外地址」，二维码中的 Endpoint 为空，请到系统设置中填写公网域名或 IP"
	}
	return endpointForInterface(ip, it.ListenPort),
		"当前 Endpoint 使用自动探测的本机地址，公网访问请到系统设置中配置 DDNS 域名或公网 IP"
}

// endpointForInterface 把「对外访问地址」的设置值补成这条连接可用的 host:port。
//
// 已带端口就原样返回：用户显式写了端口，意味着他自己配了「外部端口 → 本机端口」的映射，
// 本应用擅自改掉会让路由器上那条映射失效，而那只存在他自己的路由器里，改错了两边都对不上。
// 没带端口时才补上本连接的监听端口 —— 同号映射最省事，也最不容易错。
func endpointForInterface(host string, listenPort int) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	// "example.com:51820" → 已指定端口；"example.com:"（手滑留下冒号）视同没写端口。
	if h, p, err := net.SplitHostPort(host); err == nil {
		if p != "" {
			return host
		}
		host = h
	}
	// 用户可能把 IPv6 连方括号一起填进来（[fd00::1]），JoinHostPort 会再包一层，变成 [[fd00::1]]。
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	port := listenPort
	if port <= 0 {
		port = defaultListenPort
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func (s *Service) validatePeer(ctx context.Context, p *model.Peer, selfID int64) error {
	if !wgkey.Validate(p.PublicKey) {
		return fmt.Errorf("对方设备的识别码格式不正确：应为一串 44 个字符的编码")
	}
	if p.EndpointHost != "" && (p.EndpointPort <= 0 || p.EndpointPort > 65535) {
		return fmt.Errorf("「对方端口」填写不正确，请填写 1 到 65535 之间的数字")
	}
	if err := validateCIDRList("分配给这台设备的内部地址", p.AllowedIPs); err != nil {
		return err
	}
	// 安全红线：服务端准入地址中出现默认路由写法，会改写 NAS 自身网络。
	if err := wgback.ValidatePeerAllowedIPs(p.AllowedIPs); err != nil {
		return err
	}
	switch p.RouteMode {
	case model.RouteModeFull, model.RouteModeLAN:
	case model.RouteModeCustom:
		if len(p.ClientAllowedIPs) == 0 {
			return fmt.Errorf("选择了「自定义可访问范围」但没有填写网段，请补充后再保存")
		}
		if err := validateCIDRList("自定义可访问范围", p.ClientAllowedIPs); err != nil {
			return err
		}
		if err := s.checkScopeConflicts(ctx, p); err != nil {
			return err
		}
	default:
		return fmt.Errorf("「设备上网方式」取值不正确，请选择：只访问家里设备 / 在外上网也走家里 / 自定义可访问范围")
	}
	if p.Keepalive < 0 || p.Keepalive > 3600 {
		return fmt.Errorf("心跳间隔需要在 0 到 3600 秒之间（推荐 25 秒）")
	}
	peers, err := s.Store.ListPeers(ctx, p.InterfaceID)
	if err != nil {
		return err
	}
	for _, other := range peers {
		if other.ID == selfID {
			continue
		}
		if other.PublicKey == p.PublicKey {
			return fmt.Errorf("这台设备已经在当前连接中了（识别码重复），请勿重复添加")
		}
		if sameStringSet(other.AllowedIPs, p.AllowedIPs) && len(p.AllowedIPs) > 0 {
			return fmt.Errorf("「允许通行的地址」与设备「%s」完全相同，两台设备会冲突，请修改后重试", other.Name)
		}
	}
	return s.checkPeerAddrOverlap(ctx, p, selfID)
}

// hasIPv4Addr 判断地址列表里是否已经有 IPv4 项。
func hasIPv4Addr(list []string) bool {
	for _, a := range list {
		if ip, _, err := net.ParseCIDR(strings.TrimSpace(a)); err == nil && ip.To4() != nil {
			return true
		}
	}
	return false
}

// hostOverlaps 判断「一个主机地址」（/32）是否与另一项声明冲突。
//
// 只从一侧判断（主机地址是否落在对方声明的范围里）：另一侧若是更宽的网段（例如有人把设备
// 写成 `10.20.0.9/24`），那它确实声明了整段，落在其中的主机地址就真的会与它抢流量。
func hostOverlaps(host, other string) bool {
	hip, _, err := net.ParseCIDR(strings.TrimSpace(host))
	if err != nil {
		return false
	}
	_, on, err := net.ParseCIDR(strings.TrimSpace(other))
	if err != nil {
		return false
	}
	return on.Contains(hip)
}

// tunnelPrefixLens 取本连接隧道网段的掩码长度（v4 → 前缀长度）。
//
// 有多个网段时取**最长**的那个：判据是「声明是否细到能与设备地址直接比较」，
// 取最长的等于用最严的那条网段做门槛。
func tunnelPrefixLens(it *model.Interface) map[int]int {
	out := map[int]int{}
	for _, a := range it.Addresses {
		_, n, err := net.ParseCIDR(strings.TrimSpace(a))
		if err != nil {
			continue
		}
		fam := 6
		if n.IP.To4() != nil {
			fam = 4
		}
		ones, _ := n.Mask.Size()
		if cur, ok := out[fam]; !ok || ones > cur {
			out[fam] = ones
		}
	}
	return out
}

// comparableWithTunnel 判断「对端条目声明的一项」是否细到能与本机设备地址直接比较。
//
// 比本连接隧道网段**更宽**的声明一律跳过：那是「对端整个地址空间都能进来」这类准入声明
// （例如把对端内网写成 10.0.0.0/8），本机自己的隧道地址本来就落在它里面 ——
// 拿它来比会把这条连接上的每一台设备都判成冲突，用户什么也做不了。
func comparableWithTunnel(entry string, tunnelOnes map[int]int) bool {
	_, n, err := net.ParseCIDR(strings.TrimSpace(entry))
	if err != nil {
		return false
	}
	fam := 6
	if n.IP.To4() != nil {
		fam = 4
	}
	ones, _ := n.Mask.Size()
	limit, ok := tunnelOnes[fam]
	if !ok {
		return true // 本连接没有这一族的网段：不做判断，交给其它校验
	}
	return ones >= limit
}

// checkPeerAddrOverlap 检查这台设备的隧道地址是否与「本机这条连接的专用地址」或
// 「同一连接里其它条目已占用的隧道地址」**重叠**。
//
// 为什么必须拦「重叠」而不只是「完全相同」（真机踩到过）：WireGuard 的准入地址是一张
// 按前缀索引的表，本机发往 X 的包会交给「声明了 X 的那个节点」。只要两个节点都声明了同一个
// 地址，其中一个就必然收不到 —— 而只比对「集合完全相同」时，
// {10.20.0.3/32} 与 {10.20.0.3/32, 192.168.2.0/24} 会被判成「不冲突」而放行，
// 于是「设备」与「对端 NAS 条目」抢同一个地址也能存下来：对端 NAS 在界面上看着在线
// （握手走的是公钥与对外地址，与内网地址无关），实际永远不通，且没有任何提示。
//
// 两类**不算冲突**的项要先排除，否则会制造大量假冲突：
//
//  1. 对端内网网段（192.168.2.0/24 这类）不是「某个节点的隧道地址」，它们落在隧道之外，
//     在取「本连接隧道内的地址」时就已经被排除；
//  2. 比本连接隧道网段更宽的声明，见 comparableWithTunnel。
func (s *Service) checkPeerAddrOverlap(ctx context.Context, p *model.Peer, selfID int64) error {
	it, err := s.Store.GetInterface(ctx, p.InterfaceID)
	if err != nil {
		return nil // 连接读不到时另有校验报错，不在这里重复报
	}
	tunnel := subnetListOf(it)
	// deviceAddrs 是**这台设备自己**的隧道地址 = 准入地址里落在本连接隧道网段内的那些。
	//
	// 为什么不用 p.AllowedIPs 直接比：站点条目的准入地址里还带着「对端内网网段」
	//（那些是"允许从哪些源地址进来"，不是某台设备的地址），混在一起比会把
	// 正常的对端网段也判成冲突。
	deviceAddrs := []string{}
	for _, a := range p.AllowedIPs {
		for _, sn := range tunnel {
			if subnetContains(sn, a) {
				deviceAddrs = append(deviceAddrs, a)
				break
			}
		}
	}
	if len(deviceAddrs) == 0 {
		return nil
	}
	// 与「本机这条连接的专用地址」冲突：那是把设备配成了 NAS 自己。
	//
	// 这里必须把连接地址收敛成**它自己那一个地址**再比（10.10.0.1/24 → 10.10.0.1/32）：
	// 拿 /24 整段去比的话，同网段里的每一台设备都会被判成「与 NAS 冲突」（它们本来就该
	// 落在这个网段里）—— 那会把所有正常配置全部拦下。
	for _, a := range it.Addresses {
		host := hostCIDR(a)
		if host == "" {
			continue
		}
		for _, d := range deviceAddrs {
			if hostOverlaps(host, d) {
				return fmt.Errorf("「分配给这台设备的内部地址」%s 与本机这条连接的专用地址 %s 是同一个地址："+
					"设备会和 NAS 抢同一个地址，请给设备换一个（例如该网段里靠后的位置）", d, a)
			}
		}
	}
	peers, err := s.Store.ListPeers(ctx, p.InterfaceID)
	if err != nil {
		return nil
	}
	tunnelOnes := tunnelPrefixLens(it)
	for i := range peers {
		other := &peers[i]
		if other.ID == selfID {
			continue
		}
		for _, o := range tunnelAddrsOf(it, other) {
			if !comparableWithTunnel(o, tunnelOnes) {
				continue
			}
			for _, d := range deviceAddrs {
				if cidrOverlaps(d, o) {
					who := "设备「" + other.Name + "」"
					if isSitePeer(other) {
						// 这一条最要紧：它意味着「能访问对端 NAS、却访问不了对端设备」，
						// 而现象与这个地址的关系用户完全推不出来。
						who = "对端 NAS 条目「" + other.Name + "」"
					}
					return fmt.Errorf("「分配给这台设备的内部地址」%s 与 %s 已占用的 %s 重叠："+
						"同一连接里两个条目声明同一个地址时，本机只会把发往它的流量交给其中一个，"+
						"另一个（往往就是对端的设备）会永远访问不到。请换一个地址", d, who, o)
				}
			}
		}
	}
	return nil
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) || len(a) == 0 {
		return false
	}
	m := map[string]bool{}
	for _, s := range a {
		m[s] = true
	}
	for _, s := range b {
		if !m[s] {
			return false
		}
	}
	return true
}

func idsString(ids []int64) string {
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, strconv.FormatInt(id, 10))
	}
	return strings.Join(parts, ",")
}

// nextFreeIP 在接口隧道网段内寻找空闲地址（从 .2 开始）。
func nextFreeIP(it *model.Interface, peers []model.Peer) string {
	used := map[string]bool{}
	for _, p := range peers {
		for _, a := range p.AllowedIPs {
			if ip, _, err := net.ParseCIDR(a); err == nil {
				used[ip.String()] = true
			}
		}
	}
	for _, a := range it.Addresses {
		ip, ipnet, err := net.ParseCIDR(a)
		if err != nil {
			continue
		}
		used[ip.String()] = true
		base := ipnet.IP.To4()
		if base == nil {
			continue
		}
		for i := 2; i < 255; i++ {
			cand := net.IPv4(base[0], base[1], base[2], byte(i))
			if !used[cand.String()] {
				return cand.String() + "/32"
			}
		}
	}
	return ""
}
