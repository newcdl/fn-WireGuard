// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"

	"fnwg/internal/model"
	"fnwg/internal/wgkey"
)

// 多 NAS 互联（站点到站点）：把两台 NAS 后面的内网打通。
//
// 为什么做成「邀请文件」而不是让用户两头照着填：一条能用的站点互联要在两端各写对四件事，
// 而且**四处都写对才通**——
//
//	① 隧道地址：两端必须在同一个隧道网段里各占一个地址；
//	② 对方的公钥：WireGuard 两端都要知道对方公钥，缺一边隧道就起不来；
//	③ 准入地址：对端可以用哪些源地址进来 = 对端隧道地址 + 对端内网网段；
//	④ 通行范围：自己这边暴露给对面的网段（对面要把它路由进隧道）。
//
// 手工做一遍要来回对照这四处，而错任何一处的现象都只是「不通」：不报错、也没法自查。
// 做成文件交换之后，两端的内容由同一份数据推导出来，要错也只会错在同一个地方。
//
// 安全提示（必须对用户讲清）：邀请文件里带**对端的连接私钥**——与本应用生成设备配置的做法一致
// （不带就没法让对方直接用）；代价是这份文件等同于密码，要走安全渠道交给对方。
const (
	// InterconnectKind / InterconnectVersion 用于识别与拒绝不相干的文件。
	InterconnectKind    = "fnwg-interconnect"
	InterconnectVersion = 1
	// InterconnectMTU 是站点互联的默认 MTU：跨公网要留出封装余量，1380 是常见取值。
	InterconnectMTU = 1380
	// InterconnectKeepalive 是保活间隔（秒）：两端只要有一端在 NAT 后面，
	// 就得靠它把映射维持住，否则隧道空闲一段时间后会断。
	InterconnectKeepalive = 25
	// InterconnectRemark 写进设备备注，便于在设备列表里认出这条条目的来历。
	InterconnectRemark = "站点互联"
)

// InterconnectInput 是「生成互联邀请」的输入。
type InterconnectInput struct {
	// PeerName 对端 NAS 在设备列表里的名字。
	PeerName string `json:"peer_name"`
	// PeerLANSubnets 对端（要互联的那一侧）的局域网网段，至少要有一个。
	PeerLANSubnets []string `json:"peer_lan_subnets"`
	// PeerEndpoint 对端的对外地址（host:port），可以留空：
	// 留空时本端不会主动去连对端，由对端来连本端（至少一端要能被动接受连接）。
	PeerEndpoint string `json:"peer_endpoint"`
	// LocalLANSubnets 本机暴露给对端的网段；留空则用探测到的家里网段。
	LocalLANSubnets []string `json:"local_lan_subnets"`
	// InterfaceName 新连接的名称，留空自动分配（wg0、wg1…）。
	InterfaceName string `json:"interface_name"`
	// MTU 留空用 InterconnectMTU。
	MTU int `json:"mtu"`
}

// InterconnectSite 描述互联两端里的一侧（邀请方自己，或导入方要写进对端条目的那一侧）。
type InterconnectSite struct {
	Name string `json:"name"`
	// PublicKey 是该侧连接的公钥。
	PublicKey string `json:"public_key"`
	// Endpoint 是该侧的对外地址（host:port），可能为空（对端在 NAT 后且未配置）。
	Endpoint string `json:"endpoint,omitempty"`
	// TunnelAddress 是该侧在隧道里的地址（形如 10.10.0.1/24）。
	TunnelAddress string `json:"tunnel_address"`
	// LANSubnets 是该侧暴露给对面、需要对面路由进隧道的网段。
	LANSubnets []string `json:"lan_subnets"`
}

// InterconnectPeerParams 是邀请里给对端准备的建连参数。
type InterconnectPeerParams struct {
	Name string `json:"name"`
	// PrivateKey 是对端那条连接要用的私钥：由邀请方生成，随文件交给对方。
	PrivateKey string `json:"private_key"`
	// TunnelAddress 是对端在隧道里的地址（与 TunnelSubnet 同网段）。
	TunnelAddress string `json:"tunnel_address"`
	// TunnelSubnet 是两端共用的隧道网段。
	TunnelSubnet string `json:"tunnel_subnet"`
	MTU          int    `json:"mtu"`
}

// InterconnectInvite 是互联邀请文件的内容（JSON）。
type InterconnectInvite struct {
	Kind    string                 `json:"kind"`
	Version int                    `json:"version"`
	Site    InterconnectSite       `json:"site"`
	Peer    InterconnectPeerParams `json:"peer"`
}

// InterconnectCreated 是生成邀请的结果：本端已经建好的东西 + 要交给对方的文件。
type InterconnectCreated struct {
	InterfaceID   int64  `json:"interface_id"`
	InterfaceName string `json:"interface_name"`
	PeerID        int64  `json:"peer_id"`
	// TunnelSubnet / PeerTunnelAddress 供界面显示「隧道网段与对端地址」。
	TunnelSubnet      string `json:"tunnel_subnet"`
	PeerTunnelAddress string `json:"peer_tunnel_address"`
	// Invite 是结构化邀请（界面也可直接序列化它，但用 InviteJSON 更稳妥）。
	Invite InterconnectInvite `json:"invite"`
	// InviteJSON 是给用户复制/下载的文本，与 Invite 同源。
	InviteJSON string `json:"invite_json"`
	// PeerConf 是给「对端不装本应用」的场景用的 wg-quick 配置文本。
	PeerConf string `json:"peer_conf"`
	// Warnings 是必须让用户知道但不至于失败的事（私钥随文件走、缺少对外地址等）。
	Warnings []string `json:"warnings"`
}

// InterconnectImported 是导入结果。
type InterconnectImported struct {
	InterfaceID   int64    `json:"interface_id"`
	InterfaceName string   `json:"interface_name"`
	PeerID        int64    `json:"peer_id"`
	PeerName      string   `json:"peer_name"`
	TunnelAddress string   `json:"tunnel_address"`
	TunnelSubnet  string   `json:"tunnel_subnet"`
	AllowedIPs    []string `json:"allowed_ips"`
	ClientAllowed []string `json:"client_allowed_ips"`
	Warnings      []string `json:"warnings"`
}

// CreateInterconnect 生成一份互联邀请：在本机建好连接与对端条目，并给出交给对方的文件。
//
// 生成即建好本端的一半（隧道地址、端口、连接都由既有的自动分配逻辑挑，避免与已有连接冲突），
// 对方导入之后两边就通了 —— 不需要用户回来再补任何东西。
func (s *Service) CreateInterconnect(ctx context.Context, in InterconnectInput, a Actor) (*InterconnectCreated, error) {
	peerLAN, err := normalizeSubnets(in.PeerLANSubnets, true)
	if err != nil {
		return nil, fmt.Errorf("对端局域网网段：%w", err)
	}
	localLAN, err := s.exposedLANSubnets(ctx, in.LocalLANSubnets)
	if err != nil {
		return nil, err
	}
	mtu := in.MTU
	if mtu <= 0 {
		mtu = InterconnectMTU
	}

	// 本端的一条新连接：隧道地址、端口、名字都走自动分配（与「新建连接」同一套）。
	// 路由方式取 client：让本机能主动到达对端内网（走本应用自己的策略路由表，不碰系统路由）。
	enabled, autostart, allowLAN := true, true, true
	it, err := s.CreateInterface(ctx, CreateInterfaceInput{
		Name:       strings.TrimSpace(in.InterfaceName),
		MTU:        mtu,
		DNSMode:    "off",
		RouteTable: model.RouteTableClient,
		Enabled:    &enabled,
		Autostart:  &autostart,
		AllowLAN:   &allowLAN,
	}, a)
	if err != nil {
		return nil, err
	}
	tunnelSubnet := ""
	if len(it.Addresses) > 0 {
		tunnelSubnet = subnetOf(it.Addresses[0])
	}
	if tunnelSubnet == "" {
		return nil, fmt.Errorf("连接已创建，但没能确定隧道网段：请到「我的连接」检查该连接的本机专用地址")
	}
	peerAllowed := nextFreeIP(it, nil) // 形如 10.10.0.2/32，用于准入地址
	peerIP, _, err := net.ParseCIDR(peerAllowed)
	if err != nil {
		return nil, fmt.Errorf("分配对端隧道地址失败：%w", err)
	}
	// 邀请里给对方的地址必须带上隧道网段的掩码（对端直接拿它当连接地址），
	// 而准入地址要的是单主机形式 —— 两者不是一回事，混用会得到「隧道能起、内网不通」。
	tunnelMask := 24
	if _, tn, err := net.ParseCIDR(it.Addresses[0]); err == nil {
		if ones, bits := tn.Mask.Size(); bits == 32 {
			tunnelMask = ones
		}
	}
	peerTunnelAddr := fmt.Sprintf("%s/%d", peerIP.String(), tunnelMask)

	// 对端在本端的条目：准入地址=对端隧道地址+对端内网网段；通行范围=本机暴露的网段。
	// 公钥由本端生成（GenerateKeys），这样邀请文件里能直接带上对端要用的私钥。
	host, port := splitHostPort(in.PeerEndpoint)
	peerName := strings.TrimSpace(in.PeerName)
	if peerName == "" {
		peerName = "对端 NAS"
	}
	allowed := append([]string{peerAllowed}, peerLAN...)
	p, err := s.CreatePeer(ctx, PeerInput{
		InterfaceID:      it.ID,
		Name:             peerName,
		AllowedIPs:       allowed,
		RouteMode:        model.RouteModeCustom,
		ClientAllowedIPs: localLAN,
		EndpointHost:     host,
		EndpointPort:     port,
		Keepalive:        InterconnectKeepalive,
		GenerateKeys:     true,
		Enabled:          &enabled,
		Remark:           InterconnectRemark,
	}, a)
	if err != nil {
		return nil, err
	}
	if !wgkey.Validate(p.ClientPrivateKey) {
		return nil, fmt.Errorf("对端连接的私钥没能生成，请重试；若反复出现请反馈此问题")
	}

	out := &InterconnectCreated{
		InterfaceID:       it.ID,
		InterfaceName:     it.Name,
		PeerID:            p.ID,
		TunnelSubnet:      tunnelSubnet,
		PeerTunnelAddress: peerIP.String(),
	}
	endpoint, epWarn := s.serverEndpoint(ctx, it)
	sitePub, err := wgkey.PublicKey(it.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("导出本机公钥失败：%w", err)
	}
	out.Invite = InterconnectInvite{
		Kind:    InterconnectKind,
		Version: InterconnectVersion,
		Site: InterconnectSite{
			Name:          it.Name,
			PublicKey:     sitePub,
			Endpoint:      endpoint,
			TunnelAddress: it.Addresses[0],
			LANSubnets:    localLAN,
		},
		Peer: InterconnectPeerParams{
			Name:       peerName,
			PrivateKey: p.ClientPrivateKey,
			// 对端在隧道里的地址：本机地址之外的下一个空闲地址（见 nextFreeIP）。
			TunnelAddress: peerTunnelAddr,
			TunnelSubnet:  tunnelSubnet,
			MTU:           mtu,
		},
	}
	raw, err := json.MarshalIndent(out.Invite, "", "  ")
	if err != nil {
		return nil, err
	}
	out.InviteJSON = string(raw)

	// 顺便给一份 wg-quick 配置：对端没装本应用时照着它填就能用。
	if res, err := s.PeerConfig(ctx, p.ID); err == nil {
		out.PeerConf = res.Conf
		if res.Warning != "" {
			out.Warnings = appendWarning(out.Warnings, res.Warning)
		}
	}

	if epWarn != "" {
		out.Warnings = appendWarning(out.Warnings, epWarn)
	}
	if endpoint == "" {
		out.Warnings = append(out.Warnings,
			"本机没有对外地址，对端无法主动连过来：请先在「系统设置 → 接入设置」填写家里的公网域名或 IP，再重新生成一次邀请")
	}
	if strings.TrimSpace(in.PeerEndpoint) == "" {
		out.Warnings = append(out.Warnings,
			"没填对端的对外地址，本机不会主动去连对端：隧道要由对端发起（对端有公网地址，或对端在导入后填上你的地址）")
	}
	out.Warnings = append(out.Warnings,
		"邀请文件里含对端连接的私钥，等同于密码：请通过安全渠道交给对方，不要发到群里或上传网盘")

	s.audit(ctx, a, "interconnect.create", "interface", fmt.Sprint(it.ID), "", it.Name, "ok",
		fmt.Sprintf("生成互联邀请：隧道 %s，对端 %s，暴露本机网段 %s", tunnelSubnet, peerTunnelAddr, strings.Join(localLAN, "、")))
	return out, nil
}

// ImportInterconnect 导入一份互联邀请：在本机建立对称的连接与对端条目。
//
// 导入前把所有能提前查出来的冲突都挡住（隧道网段与已有连接重叠、两端内网网段撞车、
// 公钥重复、私钥格式不对）—— 建完再发现就只能删连接重来，而那些冲突的表现都是「不通」。
func (s *Service) ImportInterconnect(ctx context.Context, inv InterconnectInvite, a Actor) (*InterconnectImported, error) {
	if err := ValidateInterconnectInvite(inv); err != nil {
		return nil, err
	}
	tunnelSubnet := subnetOf(inv.Peer.TunnelAddress)

	// 1) 隧道网段不能与本机已有连接重叠：两端的隧道网段必须一致，
	//    所以这里不能「自动换一个」——只能请对方换，提示必须写清这一点。
	ifaces, err := s.Store.ListInterfaces(ctx)
	if err != nil {
		return nil, err
	}
	probe := &model.Interface{Name: "待导入", Addresses: []string{inv.Peer.TunnelAddress}}
	if err := checkInterfaceConflicts(probe, ifaces); err != nil {
		// 最常见的冲突其实是「同一份邀请导入了两次」：那时已有连接的隧道网段与邀请完全一样，
		// 而按通用提示（让对方换网段）去处理，用户会越走越远 —— 这里单独认出来。
		if dup := s.findInterconnectByTunnel(ctx, ifaces, tunnelSubnet); dup != "" {
			return nil, fmt.Errorf("本机已经有一条用隧道网段 %s 的互联连接（%s）："+
				"多半是把同一份邀请导入了两次，到「我的连接」看一眼即可", tunnelSubnet, dup)
		}
		return nil, fmt.Errorf("邀请里的隧道网段 %s 与本机已有连接冲突（%w）；"+
			"两端的隧道网段必须一致，请让对方换一个隧道网段后重新生成邀请", tunnelSubnet, err)
	}
	// 2) 两端的内网网段不能撞车：撞车时「谁访问谁」根本说不清，路由也会互相覆盖。
	for _, ours := range s.homeLANSubnets(ctx) {
		for _, theirs := range inv.Site.LANSubnets {
			if cidrOverlaps(ours, theirs) {
				return nil, fmt.Errorf("对端内网网段 %s 与本机内网网段 %s 重叠："+
					"两端的内网网段不能相同，请先在其中一侧改掉局域网网段", theirs, ours)
			}
		}
	}
	// 3) 对端公钥不能已经在用：同一个公钥出现在两处，内核里的节点会互相顶掉。
	if err := s.checkPublicKeyFree(ctx, inv.Site.PublicKey, ifaces); err != nil {
		return nil, err
	}

	localLAN, err := s.exposedLANSubnets(ctx, nil)
	if err != nil {
		return nil, err
	}
	// 建连接：私钥与隧道地址用邀请里给的（两端由此配对）。
	enabled, autostart, allowLAN := true, true, true
	mtu := inv.Peer.MTU
	if mtu <= 0 {
		mtu = InterconnectMTU
	}
	it, err := s.CreateInterface(ctx, CreateInterfaceInput{
		MTU:        mtu,
		Addresses:  []string{inv.Peer.TunnelAddress},
		PrivateKey: inv.Peer.PrivateKey,
		DNSMode:    "off",
		RouteTable: model.RouteTableClient,
		Enabled:    &enabled,
		Autostart:  &autostart,
		AllowLAN:   &allowLAN,
	}, a)
	if err != nil {
		return nil, err
	}
	host, port := splitHostPort(inv.Site.Endpoint)
	allowed := append([]string{hostCIDR(inv.Site.TunnelAddress)}, inv.Site.LANSubnets...)
	peerName := strings.TrimSpace(inv.Site.Name)
	if peerName == "" {
		peerName = "对端 NAS"
	}
	p, err := s.CreatePeer(ctx, PeerInput{
		InterfaceID:      it.ID,
		Name:             peerName,
		PublicKey:        inv.Site.PublicKey,
		AllowedIPs:       allowed,
		RouteMode:        model.RouteModeCustom,
		ClientAllowedIPs: localLAN,
		EndpointHost:     host,
		EndpointPort:     port,
		Keepalive:        InterconnectKeepalive,
		Enabled:          &enabled,
		Remark:           InterconnectRemark,
	}, a)
	if err != nil {
		return nil, err
	}

	out := &InterconnectImported{
		InterfaceID:   it.ID,
		InterfaceName: it.Name,
		PeerID:        p.ID,
		PeerName:      peerName,
		TunnelAddress: inv.Peer.TunnelAddress,
		TunnelSubnet:  tunnelSubnet,
		AllowedIPs:    allowed,
		ClientAllowed: localLAN,
	}
	if strings.TrimSpace(inv.Site.Endpoint) == "" {
		out.Warnings = append(out.Warnings,
			"邀请里没有对端的对外地址，本机无法主动去连对端：请让对端先发起连接（或稍后在设备里补填对端地址）")
	}
	out.Warnings = append(out.Warnings,
		"两端内网里的普通主机要互相访问，还需要在局域网侧把对端网段的路由指到本机（NAS 自身与连上隧道的设备不受影响）")

	s.audit(ctx, a, "interconnect.import", "interface", fmt.Sprint(it.ID), "", it.Name, "ok",
		fmt.Sprintf("导入互联邀请：隧道 %s，对端 %s，准入 %s", tunnelSubnet, inv.Site.Name, strings.Join(allowed, "、")))
	return out, nil
}

// ValidateInterconnectInvite 校验邀请内容（结构与取值），不碰数据库。
//
// 单独导出：接口层拿到的是用户粘贴的文本，先解析再校验，报错要能直接给用户看。
func ValidateInterconnectInvite(inv InterconnectInvite) error {
	if inv.Kind != InterconnectKind {
		return fmt.Errorf("这不是本应用的互联邀请（缺少标识 %s）", InterconnectKind)
	}
	if inv.Version <= 0 || inv.Version > InterconnectVersion {
		return fmt.Errorf("邀请来自更新版本的应用（v%d），请先升级本应用再导入", inv.Version)
	}
	if !wgkey.Validate(inv.Site.PublicKey) {
		return fmt.Errorf("邀请里对端连接的识别码格式不正确，文件可能已损坏")
	}
	if !wgkey.Validate(inv.Peer.PrivateKey) {
		return fmt.Errorf("邀请里对端连接的私钥格式不正确，文件可能已损坏")
	}
	if _, _, err := net.ParseCIDR(strings.TrimSpace(inv.Site.TunnelAddress)); err != nil {
		return fmt.Errorf("邀请里对端的隧道地址不合法")
	}
	_, peerNet, err := net.ParseCIDR(strings.TrimSpace(inv.Peer.TunnelAddress))
	if err != nil || peerNet.IP.To4() == nil {
		return fmt.Errorf("邀请里给你的隧道地址不合法")
	}
	// 一条判据就够：地址必须落在声明的隧道网段里。
	// 分成「掩码对不上」与「不在网段内」两条只会让信息重复，用户能做的处理是同一件事。
	if !subnetContains(inv.Peer.TunnelSubnet, inv.Peer.TunnelAddress) {
		return fmt.Errorf("邀请里给你的隧道地址 %s 不在隧道网段 %s 内：文件可能已损坏",
			inv.Peer.TunnelAddress, inv.Peer.TunnelSubnet)
	}
	if _, err := normalizeSubnets(inv.Site.LANSubnets, false); err != nil {
		return fmt.Errorf("邀请里对端的内网网段有问题：%w", err)
	}
	return nil
}

// ParseInterconnectInvite 解析用户粘贴/上传的邀请文本。
func ParseInterconnectInvite(raw []byte) (InterconnectInvite, error) {
	var inv InterconnectInvite
	if err := json.Unmarshal(raw, &inv); err != nil {
		return inv, fmt.Errorf("无法识别这份内容：请确认复制的是完整的邀请文本（以 { 开头、以 } 结尾）")
	}
	if err := ValidateInterconnectInvite(inv); err != nil {
		return inv, err
	}
	return inv, nil
}

// appendWarning 追加一条提醒并去重。
//
// 同一条事实可能从两处返回（例如「Endpoint 是自动探测的」既来自 serverEndpoint、
// 也来自设备配置生成），直接追加会在界面上变成两条一模一样的提醒 ——
// 提醒重复会让人以为有两个问题。
func appendWarning(list []string, msg string) []string {
	if strings.TrimSpace(msg) == "" {
		return list
	}
	for _, v := range list {
		if v == msg {
			return list
		}
	}
	return append(list, msg)
}

// exposedLANSubnets 决定「本机暴露给对端的网段」：用户填了就用它，没填就用探测到的家里网段。
func (s *Service) exposedLANSubnets(ctx context.Context, input []string) ([]string, error) {
	if len(input) > 0 {
		out, err := normalizeSubnets(input, true)
		if err != nil {
			return nil, fmt.Errorf("要暴露给对端的网段：%w", err)
		}
		return out, nil
	}
	out, err := normalizeSubnets(s.homeLANSubnets(ctx), false)
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("没能探测到本机的局域网网段：请手工填写要暴露给对端的网段（例如 192.168.1.0/24）")
	}
	return out, nil
}

// findInterconnectByTunnel 找出「隧道网段与给定网段一致、且带站点互联条目」的连接名。
//
// 用途只有一个：把「重复导入同一份邀请」这种情况从通用冲突里认出来，给一句能对上现象的解释。
func (s *Service) findInterconnectByTunnel(ctx context.Context, ifaces []model.Interface, tunnelSubnet string) string {
	for _, it := range ifaces {
		same := false
		for _, a := range it.Addresses {
			if subnetOf(a) == tunnelSubnet {
				same = true
			}
		}
		if !same {
			continue
		}
		peers, err := s.Store.ListPeers(ctx, it.ID)
		if err != nil {
			continue
		}
		for _, p := range peers {
			if strings.HasPrefix(p.Remark, InterconnectRemark) {
				return it.Name
			}
		}
	}
	return ""
}

// checkPublicKeyFree 确认这个公钥没有被本机任何连接或设备占用。
//
// 同一个公钥出现在两处，内核里的两个节点会互相顶掉，现象是「隧道时通时不通」——
// 等到那时候再查要花很久，所以在导入时直接挡住。
func (s *Service) checkPublicKeyFree(ctx context.Context, pub string, ifaces []model.Interface) error {
	for _, it := range ifaces {
		own, err := wgkey.PublicKey(it.PrivateKey)
		if err != nil {
			continue
		}
		if own == pub {
			return fmt.Errorf("这份邀请里的公钥已经是本机连接「%s」在用：说明它其实是发回给你自己的那份，请核对文件", it.Name)
		}
		peers, err := s.Store.ListPeers(ctx, it.ID)
		if err != nil {
			continue
		}
		for _, p := range peers {
			if p.PublicKey == pub {
				return fmt.Errorf("这份邀请里的公钥已经被设备「%s」占用：请让对方重新生成一份邀请", p.Name)
			}
		}
	}
	return nil
}

// normalizeSubnets 规范化网段列表：去空白、只留 IPv4、掩掉主机位、去重。
//
// 刻意拒绝默认路由写法（0.0.0.0/0）：把「内网网段」写成全网，等于把对端的所有流量
// 都拉进隧道 —— 在这里挡住远比事后排查便宜。
func normalizeSubnets(list []string, requireAtLeastOne bool) ([]string, error) {
	out := []string{}
	for _, raw := range list {
		v := strings.TrimSpace(raw)
		if v == "" {
			continue
		}
		_, n, err := net.ParseCIDR(v)
		if err != nil || n.IP.To4() == nil {
			return nil, fmt.Errorf("%q 不是合法的 IPv4 网段，写成 192.168.2.0/24 这样", v)
		}
		if ones, bits := n.Mask.Size(); bits == 32 && ones == 0 {
			return nil, fmt.Errorf("不能用 0.0.0.0/0：那是「所有地址」，会把对端的全部上网流量也拉进隧道")
		}
		masked := maskCIDR(n)
		if !containsString(out, masked) {
			out = append(out, masked)
		}
	}
	if requireAtLeastOne && len(out) == 0 {
		return nil, fmt.Errorf("至少要填一个网段")
	}
	return out, nil
}

// maskCIDR 把网段归一化成网络地址形式（去掉主机位）。
func maskCIDR(n *net.IPNet) string {
	return (&net.IPNet{IP: n.IP.Mask(n.Mask), Mask: n.Mask}).String()
}

// subnetOf 返回某个地址所属的网段（10.10.0.1/24 → 10.10.0.0/24）。
func subnetOf(addr string) string {
	_, n, err := net.ParseCIDR(strings.TrimSpace(addr))
	if err != nil {
		return ""
	}
	return maskCIDR(n)
}

// hostCIDR 把「隧道地址」化成单主机网段（10.10.0.2/24 → 10.10.0.2/32）。
//
// 准入地址要的是「这个对端自己的地址」，写成 /24 会把整段都当成它的来源。
func hostCIDR(addr string) string {
	ip, _, err := net.ParseCIDR(strings.TrimSpace(addr))
	if err != nil || ip.To4() == nil {
		return ""
	}
	return ip.String() + "/32"
}

// subnetContains 判断 addr 是否落在 parent 网段内。
func subnetContains(parent, addr string) bool {
	_, pn, err := net.ParseCIDR(strings.TrimSpace(parent))
	if err != nil {
		return false
	}
	ip, _, err := net.ParseCIDR(strings.TrimSpace(addr))
	if err != nil {
		return false
	}
	return pn.Contains(ip)
}

// cidrOverlaps 判断两个网段是否重叠（用于挡住「两端内网网段撞车」）。
func cidrOverlaps(a, b string) bool {
	_, an, err := net.ParseCIDR(strings.TrimSpace(a))
	if err != nil {
		return false
	}
	bip, bn, err := net.ParseCIDR(strings.TrimSpace(b))
	if err != nil {
		return false
	}
	return an.Contains(bip) || bn.Contains(an.IP)
}

// splitHostPort 把「host:port」拆开；留空或只有主机名时端口为 0（由对端决定）。
func splitHostPort(endpoint string) (host string, port int) {
	v := strings.TrimSpace(endpoint)
	if v == "" {
		return "", 0
	}
	h, p, err := net.SplitHostPort(v)
	if err != nil {
		// 没写端口（例如只填了域名）：仍然可用，端口交给默认值
		return strings.Trim(v, "[]"), 0
	}
	n, err := strconv.Atoi(p)
	if err != nil || n <= 0 || n > 65535 {
		return h, 0
	}
	return h, n
}
