// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sort"
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
	// InstallID 是该侧的「安装标识」（见 SettingInstallID），**可选字段**。
	//
	// 它只服务一件事：让导入端看出「两台机器的默认网段基准是同一个」——那说明两边是
	// 同一份数据装出来的（多半是把一台的整机数据拷到了另一台），此时各自以后新建的连接
	// 仍会挑到同一个网段，得当场点破。老邀请没有这一项，导入端跳过即可。
	InstallID string `json:"install_id,omitempty"`
	// OccupiedSubnets 是本侧**全部连接**的隧道网段清单，可选字段（老邀请没有它）。
	//
	// 为什么要把这些告诉对方：两端 NAS 的自动分配是各自独立的，两边的第 N 条连接
	// 有可能选到同一个网段，于是两端设备地址成对重复（都是 .2、.3…）。隧道本身照样能通，
	// 所以**不拒绝导入**，但必须当场说清 —— 否则用户只会看到「能访问对端内网，
	// 就是访问不了对端的某几台设备」，而现象与地址撞车的关系完全推不出来。
	//
	// 导入端还会把它**落库**（model.Peer.SiteOccupied），供之后新建连接自动避开与体检比对。
	OccupiedSubnets []string `json:"occupied_subnets,omitempty"`
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
	// PresharedKey 是这条互联的「二次加密口令」（两端必须完全一致）。
	//
	// 必须随邀请一起交给对方：邀请方给自己那条对端条目生成了口令，对端若不知道，
	// 握手会因口令不一致被**直接拒绝** —— 现象只是「设备一直离线、最近通信从未」，
	// 此时端口映射、公网地址、FRP 全都是对的也无济于事（真机踩到过：
	// 两端流量在涨、却一次都没握上手，很难往口令上想）。
	PresharedKey string `json:"preshared_key"`
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
	// PortNote 是「对外地址的端口 ≠ 本连接监听端口」时的提示（为空表示一致，无需提示）。
	PortNote string `json:"port_note,omitempty"`
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
	// ListenPort 是本机这条连接实际监听的 UDP 端口；PublicEndpoint 是对外访问地址。
	// 两者一起给出来，用户才能核对「外部端口 → 本机端口」这段映射（端口可以不同，
	// 但必须真的转得通，否则表现只是「对端连不上本机」，谁也看不出是端口的事）。
	ListenPort     int    `json:"listen_port"`
	PublicEndpoint string `json:"public_endpoint"`
	// PortNote 是两者不一致时的提示（为空表示一致）。
	PortNote string   `json:"port_note,omitempty"`
	Warnings []string `json:"warnings"`
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
		DNSMode:    model.DNSModeOff,
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
	if _, _, perr := net.ParseCIDR(peerAllowed); perr != nil {
		return nil, fmt.Errorf("分配对端隧道地址失败：%w", perr)
	}

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
	// 口令同样必须存在：它要随邀请交给对方，缺了就会变成「两端永远握不上手」。
	if !wgkey.Validate(p.PresharedKey) {
		return nil, fmt.Errorf("对端连接的二次加密口令没能生成，请重试；若反复出现请反馈此问题")
	}

	endpoint, epWarn := s.serverEndpoint(ctx, it)
	// 邀请的组装与「再次查看邀请」共用同一份推导（buildInterconnectInvite）：
	// 两处各写一遍，迟早会出现「当初生成的那份」与「后来看到的那份」不一致。
	inv, err := buildInterconnectInvite(it, p, endpoint, s.installID(ctx), s.occupiedTunnelSubnets(ctx))
	if err != nil {
		return nil, err
	}
	out := &InterconnectCreated{
		InterfaceID:       it.ID,
		InterfaceName:     it.Name,
		PeerID:            p.ID,
		TunnelSubnet:      inv.Peer.TunnelSubnet,
		PeerTunnelAddress: hostIP(inv.Peer.TunnelAddress),
		Invite:            inv,
		PortNote:          portNoteIfMismatch(it, endpoint),
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
		"邀请文件里含对端连接的私钥与二次加密口令，等同于密码：请通过安全渠道交给对方，不要发到群里或上传网盘")
	out.Warnings = append(out.Warnings,
		"对端导入后两处内网即互通；连上本机的设备会自动带上对端内网，可访问两处的机器"+
			"（已连上的设备需重新扫码一次，让新范围写进它的配置）")

	s.audit(ctx, a, "interconnect.create", "interface", fmt.Sprint(it.ID), "", it.Name, "ok",
		fmt.Sprintf("生成互联邀请：隧道 %s，对端 %s，暴露本机网段 %s",
			out.TunnelSubnet, out.PeerTunnelAddress, strings.Join(localLAN, "、")))
	return out, nil
}

// buildInterconnectInvite 由「本机连接 + 对端条目」推导出邀请内容。
//
// 「生成邀请」与「再次查看邀请」都走这一份推导：邀请里的每一项都能从库里推出来
// （连接私钥 → 公钥、连接地址 → 隧道网段、条目准入地址 → 对端隧道地址、
// 条目的代管私钥与口令 → 要交给对方的东西），因此不需要另外存档一份 ——
// 存档反而要再存一遍私钥与口令，收益低、风险高。
func buildInterconnectInvite(it *model.Interface, p *model.Peer, endpoint, installID string, occupied []string) (InterconnectInvite, error) {
	if it == nil || p == nil {
		return InterconnectInvite{}, fmt.Errorf("这条互联条目已经不存在，请刷新页面后重试")
	}
	if len(it.Addresses) == 0 {
		return InterconnectInvite{}, fmt.Errorf("这条连接没有本机专用地址，推导不出邀请内容：请到「我的连接」检查该连接")
	}
	sitePub, err := wgkey.PublicKey(it.PrivateKey)
	if err != nil {
		return InterconnectInvite{}, fmt.Errorf("导出本机公钥失败：%w", err)
	}
	if !wgkey.Validate(p.ClientPrivateKey) {
		return InterconnectInvite{}, fmt.Errorf("这条条目没有代管私钥（当初是以外部识别码添加的），重现不出邀请：" +
			"请到「我的连接 → 与另一台 NAS 互联」重新生成一份，并在对端重新导入")
	}
	tunnelSubnet := subnetOf(it.Addresses[0])
	// 对端隧道地址：准入地址里落在本连接隧道网段内的那一个（形如 10.10.0.2/32）。
	peerTunnel := ""
	for _, a := range p.AllowedIPs {
		if subnetContains(tunnelSubnet, a) {
			peerTunnel = a
			break
		}
	}
	if peerTunnel == "" {
		return InterconnectInvite{}, fmt.Errorf("这条条目的准入地址里没有对端隧道地址，重现不出邀请：" +
			"请到「我的设备」检查该条目的「分配给这台设备的内部地址」")
	}
	// 掩码必须换成隧道网段的掩码：对端直接拿这个地址当自己的连接地址，
	// 写成 /32 会让它连不上本连接以外的地址（准入地址要的是 /32，两者不是一回事）。
	mask := 24
	if _, tn, err := net.ParseCIDR(it.Addresses[0]); err == nil {
		if ones, bits := tn.Mask.Size(); bits == 32 {
			mask = ones
		}
	}
	lan, err := normalizeSubnets(p.ClientAllowedIPs, false)
	if err != nil {
		return InterconnectInvite{}, fmt.Errorf("这条条目暴露给对端的网段有问题：%w", err)
	}
	return InterconnectInvite{
		Kind:    InterconnectKind,
		Version: InterconnectVersion,
		Site: InterconnectSite{
			Name:            it.Name,
			PublicKey:       sitePub,
			Endpoint:        endpoint,
			TunnelAddress:   it.Addresses[0],
			LANSubnets:      lan,
			InstallID:       installID,
			OccupiedSubnets: occupied,
		},
		Peer: InterconnectPeerParams{
			Name:       p.Name,
			PrivateKey: p.ClientPrivateKey,
			// 口令必须随邀请交出去：本端那条对端条目已经带着它，对端不知道就会握手失败。
			PresharedKey:  p.PresharedKey,
			TunnelAddress: fmt.Sprintf("%s/%d", hostIP(peerTunnel), mask),
			TunnelSubnet:  tunnelSubnet,
			MTU:           it.MTU,
		},
	}, nil
}

// InterconnectInvite 重现一份已生成的互联邀请。
//
// 内容全部由当前状态推导，不落库；邀请含对端私钥与口令，因此调用方必须按
// 「查看密钥」同级权限（model.PermKeyReveal）校验，并留下审计。
//
// 它反映的是**当前**设置：若对外地址等在这之后改过，重现出来的会与当初那份不同，
// 界面要提示「把新的这份重新交给对端导入」。
func (s *Service) InterconnectInvite(ctx context.Context, peerID int64, a Actor) (*InterconnectCreated, error) {
	p, err := s.Store.GetPeer(ctx, peerID)
	if err != nil {
		return nil, fmt.Errorf("这条条目不存在，请刷新页面后重试")
	}
	if !isSitePeer(p) {
		return nil, fmt.Errorf("这不是互联条目：只有备注以「%s」开头的对端条目才有对应的邀请", InterconnectRemark)
	}
	it, err := s.Store.GetInterface(ctx, p.InterfaceID)
	if err != nil {
		return nil, fmt.Errorf("这条条目所属的连接已经不存在，请刷新页面")
	}
	endpoint, epWarn := s.serverEndpoint(ctx, it)
	inv, err := buildInterconnectInvite(it, p, endpoint, s.installID(ctx), s.occupiedTunnelSubnets(ctx))
	if err != nil {
		return nil, err
	}
	raw, err := json.MarshalIndent(inv, "", "  ")
	if err != nil {
		return nil, err
	}
	out := &InterconnectCreated{
		InterfaceID:       it.ID,
		InterfaceName:     it.Name,
		PeerID:            p.ID,
		TunnelSubnet:      inv.Peer.TunnelSubnet,
		PeerTunnelAddress: hostIP(inv.Peer.TunnelAddress),
		Invite:            inv,
		InviteJSON:        string(raw),
		PortNote:          portNoteIfMismatch(it, endpoint),
	}
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
			"本机没有对外地址，对端无法主动连过来：请先在「系统设置 → 接入设置」填写家里的公网域名或 IP")
	}
	out.Warnings = append(out.Warnings,
		"这是按「当前」设置重新生成的一份：如果你改过对外地址，请把新的这份重新交给对端导入")
	out.Warnings = append(out.Warnings,
		"邀请文件里含对端连接的私钥与二次加密口令，等同于密码：请通过安全渠道交给对方")

	s.audit(ctx, a, "interconnect.invite_view", "peer", fmt.Sprint(p.ID), "", p.Name, "ok", "查看已生成的互联邀请")
	return out, nil
}

// portNoteIfMismatch 在「对外访问地址的端口」与本连接监听端口不一致时，给出可操作的提示。
//
// 两者**可以不同**（靠路由器端口映射或内网穿透换算），但必须真的转得通。
// 这类错配的现象只有「对端一直连不上本机」，从状态与日志里都看不出与端口有关 ——
// 真机踩到过：路由器把外部 51821 转到本机 51821，而本机实际监听 51820。
func portNoteIfMismatch(it *model.Interface, endpoint string) string {
	if it == nil || it.ListenPort <= 0 {
		return ""
	}
	_, ext := splitHostPort(endpoint)
	if ext == 0 || ext == it.ListenPort {
		return ""
	}
	return fmt.Sprintf("对外访问地址用的是 %d 端口，本连接的监听端口是 %d："+
		"两者可以不同（靠路由器端口映射或内网穿透换算），但必须真的转得通 —— "+
		"请确认「外部 %d」确实转到了「本机 %d」；设备或对端一直连不上时，先查这一条",
		ext, it.ListenPort, ext, it.ListenPort)
}

// hostIP 取 CIDR 里的地址部分（10.10.0.2/32 → 10.10.0.2）。
func hostIP(cidr string) string {
	ip, _, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return strings.TrimSpace(cidr)
	}
	return ip.String()
}

// interconnectImportPlan 是「导入一份邀请」的预检结论：将要建什么、会有什么后果。
//
// 预检与执行共用同一个函数（precheckImport）：两份实现迟早会出现
// 「确认框里说一套、建出来的是另一套」，而这种不一致用户只能靠事后比对才能发现。
type interconnectImportPlan struct {
	tunnelSubnet string
	peerName     string
	// ifaceName / listenPort 是预检算出的具体取值（监听端口为 0 时按自动分配推导），
	// 用户在确认框里看到的就是它们。
	ifaceName  string
	listenPort int
	mtu        int
	allowed    []string
	localLAN   []string
	// endpointHost / endpointPort 是「本机主动去连对端」用的地址（邀请里可能为空）。
	endpointHost string
	endpointPort int
	// occupiedNote 是「两端连接网段撞车」的既有告警。
	occupiedNote string
	// peerOccupied 是对端随邀请带来的「已占用隧道网段」（规范化后）。
	// sharedTunnel 是其中与本次隧道网段重叠的那些 —— 也就是**两端共用**的互联网段。
	peerOccupied []string
	sharedTunnel []string
	// sameInstallID 表示对端与本机是同一份数据装出来的（见 installID）。
	sameInstallID bool
}

// precheckImport 把「导入会发生什么」全部算出来：校验、冲突检查、将要写入的取值。
//
// 只读：不落库、不下发、不写审计。界面在用户确认之前调用它（见 PreviewInterconnect）。
func (s *Service) precheckImport(ctx context.Context, inv InterconnectInvite, listenPort int) (*interconnectImportPlan, error) {
	if err := ValidateInterconnectInvite(inv); err != nil {
		return nil, err
	}
	if listenPort < 0 || listenPort > 65535 {
		return nil, fmt.Errorf("「本机监听端口」要填 1 到 65535 之间的数字（留空表示自动分配）")
	}
	tunnelSubnet := subnetOf(inv.Peer.TunnelAddress)

	// 1) 隧道网段不能与本机已有连接重叠：两端的隧道网段必须一致，
	//    所以这里不能「自动换一个」——只能请对方换，提示必须写清这一点。
	ifaces, err := s.Store.ListInterfaces(ctx)
	if err != nil {
		return nil, err
	}
	// 指定了端口就要当场确认它没被别的连接占用：内核里一个 UDP 端口只能有一个监听者，
	// 冲突的表现是「连接建好了却起不来」，等那时候再查又是一轮。
	if listenPort > 0 && portUsedBy(ifaces, listenPort) {
		return nil, fmt.Errorf("监听端口 %d 已经被另一条连接占用：请换一个端口，"+
			"或把路由器/内网穿透改成映射到本机正在使用的那个端口", listenPort)
	}
	probe := &model.Interface{Name: "待导入", Addresses: []string{inv.Peer.TunnelAddress}}
	if err := checkInterfaceConflicts(probe, ifaces, s.defaultAddrOffset(ctx)); err != nil {
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
	// 4) 两端的**连接网段**撞车（对端随邀请带来了它的清单；老邀请没有这一项，跳过）。
	//    不阻断导入：站点隧道本身能通，只是两端同网段里的设备互访会被本机直连路由截住。
	//    必须当场说清 —— 这条后果用户从界面上完全推不出来。
	occupiedNote := occupiedOverlapNote(inv.Site.OccupiedSubnets, ifaces)

	localLAN, err := s.exposedLANSubnets(ctx, nil)
	if err != nil {
		return nil, err
	}
	mtu := inv.Peer.MTU
	if mtu <= 0 {
		mtu = InterconnectMTU
	}
	allowed := append([]string{hostCIDR(inv.Site.TunnelAddress)}, inv.Site.LANSubnets...)
	peerName := strings.TrimSpace(inv.Site.Name)
	if peerName == "" {
		peerName = "对端 NAS"
	}
	// 接口名与监听端口都与 CreateInterface 的自动分配走同一套推导（见 applyInterfaceDefaults），
	// 这样预检给出的名字与端口就是最终结果，用户确认时才不会看到「跟说好的不一样」。
	ifaceName, err := s.nextInterfaceName(ctx)
	if err != nil {
		return nil, err
	}
	port := listenPort
	if port <= 0 {
		port = pickFreePort(ifaces, defaultIndexFor(ifaceName))
	}
	host, epPort := splitHostPort(inv.Site.Endpoint)
	// 对端占用清单宽松解析：那是对方的表述，宁可少收一条，也不该因此挡住导入。
	peerOccupiedAll := sanitizeSubnets(inv.Site.OccupiedSubnets)
	// 与本次隧道网段重叠的那些（= 两端共用的互联网段）不进台账：本机这条互联连接自己就
	// 占着它，存进来只会让「本机网段与对端占用重叠」的体检项在每条互联上都永远成立（假阳性）。
	// 它仍会出现在导入提醒里，见 peerOccupiedNote。
	shared := overlappingSubnets(peerOccupiedAll, tunnelSubnet)
	peerOccupied := subtractSubnets(peerOccupiedAll, shared)

	return &interconnectImportPlan{
		tunnelSubnet: tunnelSubnet,
		peerName:     peerName,
		ifaceName:    ifaceName,
		listenPort:   port,
		mtu:          mtu,
		allowed:      allowed,
		localLAN:     localLAN,
		endpointHost: host,
		endpointPort: epPort,
		occupiedNote: occupiedNote,
		peerOccupied: peerOccupied,
		sharedTunnel: shared,
		sameInstallID: func() bool {
			id := strings.TrimSpace(inv.Site.InstallID)
			return id != "" && id == s.installID(ctx)
		}(),
	}, nil
}

// InterconnectPreview 是「导入前预检」的结果：把即将发生的事列成一份清单交给用户确认。
//
// 为什么要有它：导入会一次性建出一条连接与一条对端条目、并往策略路由表里写若干网段，
// 而在此之前用户看到的只有「一段看不懂的文本」。确认框里必须能说出
// 「建什么、用什么地址、哪些流量会被送进隧道」，用户的确认才是有意义的。
type InterconnectPreview struct {
	// InterfaceName / TunnelAddress / TunnelSubnet / ListenPort 是将新建的连接。
	InterfaceName string `json:"interface_name"`
	TunnelAddress string `json:"tunnel_address"`
	TunnelSubnet  string `json:"tunnel_subnet"`
	ListenPort    int    `json:"listen_port"`
	// PeerName 是将新建的对端条目名。
	PeerName string `json:"peer_name"`
	// AllowedIPs 是放行对端用的来源（对端 NAS 地址 + 对端内网网段）。
	AllowedIPs []string `json:"allowed_ips"`
	// ClientAllowed 是连上本机的设备会被配置成「可访问」的范围（本机暴露给对端的网段）。
	ClientAllowed []string `json:"client_allowed_ips"`
	// RouteSubnets 是将写进本应用专用策略路由表的网段（准入地址里落在隧道网段之外的部分）。
	RouteSubnets []string `json:"route_subnets"`
	// PeerEndpoint 是「本机主动去连对端」用的地址；邀请里没带就是空（由对端发起）。
	PeerEndpoint string `json:"peer_endpoint,omitempty"`
	PortNote     string `json:"port_note,omitempty"`
	// OccupiedByPeer 是对端随邀请带来的「已占用网段」：本机今后新建连接会自动避开它们。
	OccupiedByPeer []string `json:"occupied_by_peer"`
	// Warnings 是必须让用户知道但不至于失败的事。
	Warnings []string `json:"warnings"`
}

// PreviewInterconnect 做一次导入预检：不落库、不下发，只把「将要做什么」算出来。
//
// 执行时（ImportInterconnect）会**再跑一次同一份预检**，因此预检与执行之间
// 若状态有变（端口被占、网段被占），执行会给出与预检一致的错误，而不是悄悄建成另一副样子。
func (s *Service) PreviewInterconnect(ctx context.Context, inv InterconnectInvite, listenPort int) (*InterconnectPreview, error) {
	plan, err := s.precheckImport(ctx, inv, listenPort)
	if err != nil {
		return nil, err
	}
	out := &InterconnectPreview{
		InterfaceName:  plan.ifaceName,
		TunnelAddress:  inv.Peer.TunnelAddress,
		TunnelSubnet:   plan.tunnelSubnet,
		ListenPort:     plan.listenPort,
		PeerName:       plan.peerName,
		AllowedIPs:     plan.allowed,
		ClientAllowed:  plan.localLAN,
		RouteSubnets:   routeTargets(plan.allowed, []string{inv.Peer.TunnelAddress}),
		OccupiedByPeer: plan.peerOccupied,
	}
	if plan.endpointHost != "" {
		out.PeerEndpoint = fmt.Sprintf("%s:%d", plan.endpointHost, plan.endpointPort)
	}
	// 对外地址与监听端口对不上时的提示，在这一步就能给：那正是用户在对话框里能改的端口，
	// 等建完再提示，他还得回来改一次（serverEndpoint 只用监听端口，不需要真实网卡）。
	if ep, _ := s.serverEndpoint(ctx, &model.Interface{ListenPort: plan.listenPort}); ep != "" {
		out.PortNote = portNoteIfMismatch(&model.Interface{ListenPort: plan.listenPort}, ep)
	}
	out.Warnings = importWarnings(plan, inv)
	return out, nil
}

// importWarnings 汇总导入时（以及预检时）必须让用户知道的提醒。
//
// 预检与执行共用这一份：两处各写一遍，用户就会在确认框里看到一套、结果页里看到另一套。
func importWarnings(plan *interconnectImportPlan, inv InterconnectInvite) []string {
	var out []string
	if plan.occupiedNote != "" {
		out = append(out, plan.occupiedNote)
	}
	if note := peerOccupiedNote(plan.sharedTunnel, plan.peerOccupied); note != "" {
		out = append(out, note)
	}
	if plan.sameInstallID {
		// 「安装标识」相同 = 两台机器是同一份数据装出来的（多半是把一台的整机数据拷到了另一台）。
		// 本机的默认网段基准正是从这个标识派生的，同源就意味着**以后新建连接仍会挑到同一个网段**，
		// 而那是"设备地址成对重复"的根源 —— 必须在导入这一刻就说清，否则用户只会在几天后又遇到一次。
		// 不阻断导入：站点隧道本身能通，且用户当场能做的处置只是"以后新建连接时换个网段"。
		out = append(out,
			"两台机器的「安装标识」相同：说明两边是同一份数据装出来的（多半是把一台的整机数据拷到了另一台）。"+
				"这样两边「以后新建连接的默认网段还会挑到同一个」，请在需要时把新连接的「本机专用地址」换成别的网段"+
				"（例如 10.60.0.1/24）；已经建好的连接不受影响")
	}
	if strings.TrimSpace(inv.Site.Endpoint) == "" {
		out = append(out,
			"邀请里没有对端的对外地址，本机无法主动去连对端：请让对端先发起连接（或稍后在设备里补填对端地址）")
	}
	out = append(out,
		"两台 NAS 之间已可互访对方内网；连上隧道的设备也会自动带上对端内网"+
			"（已连上的设备需重新扫码一次，让新范围写进它的配置）")
	out = append(out,
		"两端内网里的「普通主机」（没连隧道的电脑、手机）要互相访问，仍需在各自局域网的网关上加一条静态路由，"+
			"把对端网段指向本机 NAS —— 本应用不会修改你家里的路由器设置")
	return out
}

// ImportInterconnect 导入一份互联邀请：在本机建立对称的连接与对端条目。
//
// listenPort 是本机这条连接要监听的 UDP 端口，0 表示交给自动分配（推荐）。
// 之所以允许指定：外部端口与本机端口常常不一致（路由器映射、内网穿透），
// 而邀请里不带端口、界面原先也不提示，用户只能靠猜 —— 猜错的唯一现象就是「对端连不上本机」。
//
// 导入前把所有能提前查出来的冲突都挡住（隧道网段与已有连接重叠、两端内网网段撞车、
// 公钥重复、私钥格式不对、端口被占用）—— 建完再发现就只能删连接重来，而那些冲突的表现都是「不通」。
func (s *Service) ImportInterconnect(ctx context.Context, inv InterconnectInvite, listenPort int, a Actor) (*InterconnectImported, error) {
	plan, err := s.precheckImport(ctx, inv, listenPort)
	if err != nil {
		return nil, err
	}
	// 建连接：私钥与隧道地址用邀请里给的（两端由此配对）。
	enabled, autostart, allowLAN := true, true, true
	it, err := s.CreateInterface(ctx, CreateInterfaceInput{
		ListenPort: listenPort, // 0 = 自动分配（默认 51820 起，避开已有连接）
		MTU:        plan.mtu,
		Addresses:  []string{inv.Peer.TunnelAddress},
		PrivateKey: inv.Peer.PrivateKey,
		DNSMode:    model.DNSModeOff,
		RouteTable: model.RouteTableClient,
		Enabled:    &enabled,
		Autostart:  &autostart,
		AllowLAN:   &allowLAN,
	}, a)
	if err != nil {
		return nil, err
	}
	// 对端在本端的条目：准入地址 = 对端隧道地址 + 对端内网网段；通行范围 = 本机暴露的网段。
	p, err := s.CreatePeer(ctx, PeerInput{
		InterfaceID:      it.ID,
		Name:             plan.peerName,
		PublicKey:        inv.Site.PublicKey,
		PresharedKey:     strings.TrimSpace(inv.Peer.PresharedKey),
		AllowedIPs:       plan.allowed,
		RouteMode:        model.RouteModeCustom,
		ClientAllowedIPs: plan.localLAN,
		EndpointHost:     plan.endpointHost,
		EndpointPort:     plan.endpointPort,
		Keepalive:        InterconnectKeepalive,
		Enabled:          &enabled,
		Remark:           InterconnectRemark,
	}, a)
	if err != nil {
		return nil, err
	}
	// 把对端随邀请带来的「已占用网段」记在这条条目上。
	//
	// 邀请是单向的：这一步之后本机再没有别的渠道了解对端占了哪些网段 ——
	// 不记下来，今后新建连接仍会用到对端已占的网段（见 model.Peer.SiteOccupied）。
	// 失败只记日志、不影响导入：那是一份「以后少踩坑」用的台账，不值得让它挡住当前的互联。
	if err := s.Store.SetPeerSiteOccupied(ctx, p.ID, plan.peerOccupied); err != nil {
		s.Log.Warn("记录对端已占用网段失败", "peer", p.ID, "err", err)
	}

	// 把「本机监听端口 / 对外访问地址」一并回报：这两个数是核对
	// 「外部端口 → 本机端口」那条映射的唯一依据，缺了它用户只能靠猜。
	endpoint, _ := s.serverEndpoint(ctx, it)
	out := &InterconnectImported{
		InterfaceID:    it.ID,
		InterfaceName:  it.Name,
		PeerID:         p.ID,
		PeerName:       plan.peerName,
		TunnelAddress:  inv.Peer.TunnelAddress,
		TunnelSubnet:   plan.tunnelSubnet,
		AllowedIPs:     plan.allowed,
		ClientAllowed:  plan.localLAN,
		ListenPort:     it.ListenPort,
		PublicEndpoint: endpoint,
		PortNote:       portNoteIfMismatch(it, endpoint),
	}
	out.Warnings = importWarnings(plan, inv)

	s.audit(ctx, a, "interconnect.import", "interface", fmt.Sprint(it.ID), "", it.Name, "ok",
		fmt.Sprintf("导入互联邀请：隧道 %s，对端 %s，准入 %s", plan.tunnelSubnet, inv.Site.Name, strings.Join(plan.allowed, "、")))
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
	// 口令缺了不能放行：旧版邀请不带这个字段，导入后两端会一直「从未连接」，
	// 而那时现象与端口、公网、防火墙全都无关，排查成本极高 —— 在这里直接说清。
	if !wgkey.Validate(inv.Peer.PresharedKey) {
		return fmt.Errorf("这份邀请里缺少（或格式不对）两端通信必需的「二次加密口令」：" +
			"多半是旧版本生成的邀请，导入后两端会一直「从未连接」。请让对方升级后用新版重新生成一份邀请")
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

// occupiedTunnelSubnets 汇总本机全部连接的隧道网段，随邀请交给对端（见 InterconnectSite.OccupiedSubnets）。
//
// 有意**只取连接的隧道网段**、不把每台设备的 /32 也放进来：判定「两端撞车」的单位是网段，
// 设备地址只是网段里的产物；把 /32 一起带上只会让对端的提示堆成一串噪音。
func (s *Service) occupiedTunnelSubnets(ctx context.Context) []string {
	ifaces, err := s.Store.ListInterfaces(ctx)
	if err != nil {
		return nil
	}
	out := []string{}
	for i := range ifaces {
		for _, a := range ifaces[i].Addresses {
			ip, _, err := net.ParseCIDR(strings.TrimSpace(a))
			if err != nil || ip.To4() == nil {
				continue
			}
			if sn := subnetOf(a); sn != "" && !containsString(out, sn) {
				out = append(out, sn)
			}
		}
	}
	sort.Strings(out)
	return out
}

// occupiedOverlapNote 检查对端带来的「连接网段清单」是否与本机已有连接网段重叠，
// 返回给用户看的提示（没有重叠返回空）。
//
// 刻意**不阻断导入**：重叠的只是两端各自用来接设备的隧道网段，站点隧道本身照样能通。
// 但后果必须当场说清 —— 两端同网段里的设备互相访问会被本机直连路由截住（永远不通），
// 而现象与「地址撞车」的关系，用户从界面上完全推不出来（真机反馈过这条）。
func occupiedOverlapNote(occupied []string, mine []model.Interface) string {
	pairs := []string{}
	for _, o := range occupied {
		_, on, err := net.ParseCIDR(strings.TrimSpace(o))
		if err != nil {
			continue
		}
		for i := range mine {
			for _, a := range mine[i].Addresses {
				ip, an, err := net.ParseCIDR(strings.TrimSpace(a))
				if err != nil || ip.To4() == nil {
					continue
				}
				if cidrOverlap(on, an) {
					pairs = append(pairs, fmt.Sprintf("对端 %s 与本机连接「%s」的 %s", on.String(), mine[i].Name, an.String()))
				}
			}
		}
	}
	if len(pairs) == 0 {
		return ""
	}
	sort.Strings(pairs)
	shown := pairs
	if len(shown) > 2 {
		shown = shown[:2]
	}
	more := ""
	if len(pairs) > len(shown) {
		more = fmt.Sprintf("（共 %d 处）", len(pairs))
	}
	return "两端的连接网段撞车了：" + strings.Join(shown, "；") + more +
		" —— 隧道本身能通，但两端同网段里的「设备」互相访问会被本机直连路由截住（永远不通），" +
		"同一台客户端同时连两台 NAS 时地址也会冲突。" +
		"建议把其中一侧那条连接的「本机专用地址」换成别的网段（改完该连接下的设备需要重新扫码），" +
		"再重新生成一份邀请交给对端导入。"
}

// reservedSubnets 汇总「另一台 NAS 已占用」的网段：各站点条目上记着的台账。
//
// 用途有两个：新建连接的自动分配据此避让（见 pickFreeAddr），体检据此持续比对（见 inspect.go）。
//
// 为什么要把多条互联的清单合并起来而不是只认第一条：一台 NAS 可以同时与多台 NAS 互联，
// 每一条各自记着不同对端的占用情况，漏掉任何一条都可能让本机的网段撞上别人。
//
// 读失败时返回 nil 并留日志，不阻断建连接：避让是「少踩一个坑」的优化，不是正确性的前提；
// 因为读不到一张台账就让「新建连接」失败，用户只会看到一个莫名其妙的错误。
func (s *Service) reservedSubnets(ctx context.Context) []string {
	peers, err := s.Store.ListPeers(ctx, 0)
	if err != nil {
		s.Log.Warn("读取对端已占用网段失败，本次新建连接未做避让", "err", err)
		return nil
	}
	out := []string{}
	for i := range peers {
		if !isSitePeer(&peers[i]) {
			continue
		}
		for _, v := range peers[i].SiteOccupied {
			if !containsString(out, v) {
				out = append(out, v)
			}
		}
	}
	sort.Strings(out)
	return out
}

// siteReservedOverlaps 找出「本机已启用连接的网段」里与 reserved（对端已占用网段）重叠的那些，
// 返回可读描述（形如「连接「wg1」的 10.12.0.0/24」）。
//
// 只算已启用的连接：没启用的连接不参与数据面，网段撞了也不会互相截胡，报出来只是噪音。
func (s *Service) siteReservedOverlaps(ctx context.Context, reserved []string) []string {
	if len(reserved) == 0 {
		return nil
	}
	ifaces, err := s.Store.ListInterfaces(ctx)
	if err != nil {
		return nil
	}
	out := []string{}
	for i := range ifaces {
		if !ifaces[i].Enabled {
			continue
		}
		for _, a := range ifaces[i].Addresses {
			sn := subnetOf(a)
			if sn == "" {
				continue
			}
			for _, r := range reserved {
				if cidrOverlaps(sn, r) {
					desc := fmt.Sprintf("连接「%s」的 %s", ifaces[i].Name, sn)
					if !containsString(out, desc) {
						out = append(out, desc)
					}
					break
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// peerOccupiedNote 生成「对端已占用网段」的提醒，没有可说的内容时返回空串。
//
// 为什么要专门写一段：清单本身（OccupiedByPeer / 落库的 SiteOccupied）是数据，
// 而用户需要的是「这对我意味着什么」。两端各自往同一个网段里塞设备，会成对重复地址
// （都是 .2、.3…），现象却是「能访问对端 NAS、访问不了对端的某几台设备」——
// 从界面上根本推不出与地址撞车有关（真机反馈过）。
//
// others 是「值得避开」的那些（已排除共用互联网段）；shared 是两端共用的互联网段。
func peerOccupiedNote(shared, others []string) string {
	if len(others) == 0 && len(shared) == 0 {
		return ""
	}
	parts := []string{}
	if len(others) > 0 {
		parts = append(parts, fmt.Sprintf("对方 NAS 已占用这些网段：%s", strings.Join(others, "、")))
	}
	if len(shared) > 0 {
		// 共用互联网段单独点出来：它由互联本身占用，不属于「别用」清单，
		// 但恰恰是最容易被拿去挂设备的那一个（设备与隧道同连接是最常见的用法）。
		parts = append(parts, fmt.Sprintf("%s 是两端共用的互联网段（对方的隧道地址就在里面），别在这里挂设备",
			strings.Join(shared, "、")))
	}
	return strings.Join(parts, "；") +
		"。本机今后新建连接的自动分配会避开它们，但这只是「导入那一刻」对方的占用情况：" +
		"对方之后新增的连接不会自动同步过来（邀请是单向的）—— 若两端设备地址出现重复，" +
		"请到「系统维护 → 体检」里核对，那里会持续比对"
}

// sanitizeSubnets 宽松地规范化一份网段清单：跳过非法项与「所有地址」写法，不报错、不中断。
//
// 用于对端随邀请带来的清单：那是对方的表述，宁可少收一条，也不该因此挡住导入。
func sanitizeSubnets(list []string) []string {
	out := []string{}
	for _, raw := range list {
		v := strings.TrimSpace(raw)
		if v == "" {
			continue
		}
		_, n, err := net.ParseCIDR(v)
		if err != nil {
			continue
		}
		// 「所有地址」不能进清单：它会命中本机每一个连接，让避让逻辑失去意义。
		if ones, _ := n.Mask.Size(); ones == 0 {
			continue
		}
		m := maskCIDR(n)
		if !containsString(out, m) {
			out = append(out, m)
		}
	}
	sort.Strings(out)
	return out
}

// overlappingSubnets 返回 list 中与 target 网段重叠的那些（用于认出「两端共用的互联网段」）。
func overlappingSubnets(list []string, target string) []string {
	if strings.TrimSpace(target) == "" {
		return nil
	}
	out := []string{}
	for _, s := range list {
		if cidrOverlaps(s, target) {
			out = append(out, s)
		}
	}
	return out
}

// subtractSubnets 返回 list 中不在 remove 里的那些（用于把「两端共用的互联网段」剔出台账）。
func subtractSubnets(list, remove []string) []string {
	out := []string{}
	for _, s := range list {
		if !containsString(remove, s) {
			out = append(out, s)
		}
	}
	return out
}

// routeTargets 挑出「会被写进策略路由表」的网段：准入地址里落在本连接隧道网段之外的部分。
//
// 落在隧道网段内的那些（例如对端 NAS 的 /32）由内核为该网卡自动建立的直连路由覆盖，
// 本应用不需要、也不会为它们加路由（与 wgback.PlanRoutes 的取舍一致）。
// 单独算一份是为了在确认框里说清「这次会往路由表里写什么」——那正是用户最该知情的一步。
func routeTargets(allowed, addresses []string) []string {
	ifaceNets := make([]*net.IPNet, 0, len(addresses))
	for _, a := range addresses {
		if _, n, err := net.ParseCIDR(strings.TrimSpace(a)); err == nil {
			ifaceNets = append(ifaceNets, n)
		}
	}
	out := []string{}
	for _, a := range allowed {
		_, n, err := net.ParseCIDR(strings.TrimSpace(a))
		if err != nil {
			continue
		}
		covered := false
		for _, in := range ifaceNets {
			if in.Contains(n.IP) {
				covered = true
				break
			}
		}
		if !covered && !containsString(out, strings.TrimSpace(a)) {
			out = append(out, strings.TrimSpace(a))
		}
	}
	sort.Strings(out)
	return out
}
