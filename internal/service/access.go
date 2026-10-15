// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package service

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"

	"fnwg/internal/model"
	"fnwg/internal/wgback"
	"fnwg/internal/wgconf"
)

// AccessIssue 是一条「访问控制相关的设置互相矛盾」的可读结论。
type AccessIssue struct {
	// Key 是稳定标识（同类矛盾共用同一个 key），供界面归类与去重。
	Key string `json:"key"`
	// Title 一句话结论。
	Title string `json:"title"`
	// Detail 具体事实：哪条连接、哪台设备、与谁冲突。
	Detail string `json:"detail"`
	// Fix 处理建议。
	Fix string `json:"fix,omitempty"`
	// InterfaceID 涉及哪条连接，便于界面直接定位到它。
	InterfaceID int64 `json:"interface_id,omitempty"`
	// To 需要用户去处理的页面路由名。
	To string `json:"to,omitempty"`
}

// 矛盾类型。按「最该先处理」的顺序排列，逐台设备只报告优先级最高的一条 ——
// 一次抛出四条互相重叠的结论只会让用户更糊涂。
const (
	// hitAddrOutside 设备的登记地址全部落在本连接隧道网段之外 —— 这台设备物理上连不上。
	// 排在最前：它是「根本没通」，其余都是「通了但某个方向被挡住」。
	hitAddrOutside = "peer_addr_outside_tunnel"
	// hitSiteAdmitCross 站点条目放行的网段与本机另一条连接的隧道网段重叠。
	hitSiteAdmitCross = "site_admit_cross_interface"
	// hitScopeDefault 自定义通行范围里写了默认路由。
	hitScopeDefault = "scope_default_route"
	// hitScopeCross 通行范围与另一条连接的专用地址重叠。
	hitScopeCross = "scope_cross_interface"
	// hitScopeIsolate 通行范围包含隧道网段，但这条连接开着设备间隔离。
	hitScopeIsolate = "scope_blocked_by_isolation"
	// hitScopeNoLAN 通行范围包含家里网段，但这条连接的内网访问开关没打开。
	hitScopeNeedsLAN = "scope_needs_lan_access"
)

// DiagnoseAccess 检查「设备通行范围」「内网访问开关」「设备间隔离」三者互相打架的配置。
//
// 为什么必须单独做这件事：这三项设置每一项单独看都没错，组合起来却可能互相抵消，
// 而用户看到的现象只是一个模糊的「明明配了却访问不了」。
// 矛盾藏在另一个页面的另一个开关里，靠现象几乎不可能自己推出来。
//
// 结论按连接聚合：同一条连接上多台设备命中同一类矛盾时合成一条，
// 并点出设备名与台数。这样结论数量与连接数同阶，不会随设备数量膨胀。
func (s *Service) DiagnoseAccess(ctx context.Context) []AccessIssue {
	ifaces, err := s.Store.ListInterfaces(ctx)
	if err != nil {
		return nil
	}
	home := s.homeLANSubnets(ctx)
	out := []AccessIssue{}
	for i := range ifaces {
		it := &ifaces[i]
		if !it.Enabled {
			continue
		}
		peers, err := s.Store.ListPeers(ctx, it.ID)
		if err != nil {
			continue
		}
		out = append(out, s.diagnoseInterfaceAccess(ctx, it, peers, ifaces, home)...)
	}
	return out
}

// diagnoseInterfaceAccess 检查一条连接上的设备与各项开关之间的配合问题。
func (s *Service) diagnoseInterfaceAccess(ctx context.Context, it *model.Interface, peers []model.Peer, all []model.Interface, home []string) []AccessIssue {
	ownTunnel := cidrStrings(it.Addresses)
	others := make([]model.Interface, 0, len(all))
	for i := range all {
		if all[i].ID != it.ID && all[i].Enabled {
			others = append(others, all[i])
		}
	}

	// 逐台设备算出**实际生效**的通行范围，再判断它命中了哪一类矛盾。
	// 必须用 clientAllowedIPs 而不是直接看配置项：lan 模式的范围是推导出来的
	//（家里网段 + 额外放行），只看配置项会漏判也容易误判。
	hits := map[string][]string{}  // kind -> 命中的设备名
	details := map[string]string{} // kind -> 该类矛盾的具体事实
	for i := range peers {
		p := &peers[i]
		if !p.Enabled {
			continue
		}
		_, extra := wgconf.SplitClientAndServerIPs(it, p)
		scope := s.clientAllowedIPs(ctx, it, p, extra)
		name := displayPeerName(p)

		switch {
		case peerAddrsOutsideTunnel(it, p):
			// 优先级最高：这台设备**根本没通**。它的地址不在隧道网段里，配置照常生成、
			// 二维码看起来完全正常，但本机没有回到那个地址的路由，回包被直接丢弃。
			// 最容易踩到的路径：为了避免多台 NAS 撞车改了连接的网段，而旧设备地址没跟着改。
			hits[hitAddrOutside] = append(hits[hitAddrOutside], name)
			if _, ok := details[hitAddrOutside]; !ok {
				details[hitAddrOutside] = strings.Join(p.AllowedIPs, "、")
			}
		case isSitePeer(p) && crossOverlaps(extra, others):
			// 站点条目放行的网段撞上了本机另一条连接的专用地址：从本机（或它的设备）
			// 访问那个网段会被本地那条连接截住，到不了对端 —— 与「通行范围重叠」同一类问题，
			// 但方向相反，所以单独一类。
			if _, ok := details[hitSiteAdmitCross]; !ok {
				details[hitSiteAdmitCross] = crossDetail(extra, others)
			}
			hits[hitSiteAdmitCross] = append(hits[hitSiteAdmitCross], name)
		case p.RouteMode == model.RouteModeCustom && hasDefaultRoute(scope):
			hits[hitScopeDefault] = append(hits[hitScopeDefault], name)
		case crossOverlaps(scope, others):
			if _, ok := details[hitScopeCross]; !ok {
				details[hitScopeCross] = crossDetail(scope, others)
			}
			hits[hitScopeCross] = append(hits[hitScopeCross], name)
		case p.RouteMode == model.RouteModeCustom && it.IsolatePeers && len(scopeOverlaps(scope, ownTunnel)) > 0:
			details[hitScopeIsolate] = strings.Join(scopeOverlaps(scope, ownTunnel), "、")
			hits[hitScopeIsolate] = append(hits[hitScopeIsolate], name)
		case !it.AllowLAN && len(scopeOverlaps(scope, home)) > 0:
			hits[hitScopeNeedsLAN] = append(hits[hitScopeNeedsLAN], name)
		}
	}

	out := []AccessIssue{}
	// 固定顺序输出，保证界面上的呈现稳定（不会每轮刷新换位置）。
	for _, kind := range []string{hitAddrOutside, hitSiteAdmitCross, hitScopeDefault, hitScopeCross, hitScopeIsolate, hitScopeNeedsLAN} {
		names := hits[kind]
		if len(names) == 0 {
			continue
		}
		sort.Strings(names)
		out = append(out, accessIssue(kind, it, names, details[kind]))
	}
	return out
}

// accessIssue 把某一类矛盾组织成面向用户的结论。
func accessIssue(kind string, it *model.Interface, names []string, detail string) AccessIssue {
	who := fmt.Sprintf("连接「%s」上的 %s", it.Name, peerListText(names))
	issue := AccessIssue{Key: kind, InterfaceID: it.ID, To: "interfaces"}
	switch kind {
	case hitAddrOutside:
		// 处理入口在设备页：改的是那台设备的地址，不是这条连接的设置。
		issue.To = "peers"
		issue.Title = "有设备的地址不在连接的隧道网段里，它连不上"
		issue.Detail = fmt.Sprintf("%s 的登记地址是 %s，落在本连接的隧道网段 %s 之外："+
			"它的配置里会带一个隧道外的地址，握手能成、回包却没有路可走，现象只是「怎么都连不上」。",
			who, detail, strings.Join(cidrStrings(it.Addresses), "、"))
		issue.Fix = "到「我的设备」编辑它，把「分配给这台设备的内部地址」改成隧道网段内的地址" +
			"（例如该网段里的 .2），保存后重新生成二维码导入一次。" +
			"若是为了避免多台 NAS 网段撞车刚改过这条连接的网段，把该连接下的设备地址逐台改过来即可。"
	case hitSiteAdmitCross:
		issue.Title = "对端条目放行的网段与本机另一条连接撞车"
		issue.Detail = fmt.Sprintf("%s 放行的网段（%s）与本机另一条连接的专用地址重叠："+
			"从本机访问该网段会被本地那条连接截住，到不了对端。", who, detail)
		issue.Fix = "把其中一侧那条连接的「本机专用地址」换成别的网段（改完它下面的设备需要重新扫码），" +
			"或到「我的设备」把这条对端条目准入地址里重叠的网段去掉。"
	case hitScopeDefault:
		issue.Title = "有设备的通行范围写成了「全部流量」"
		issue.Detail = fmt.Sprintf("%s 的范围里含 0.0.0.0/0：设备的上网流量也会全部走这条连接，"+
			"与「只多放行一个网段」的预期完全不同。", who)
		issue.Fix = "把该设备的「设备上网方式」改成「在外上网也走家里」，这样意图才与配置一致。"
	case hitScopeCross:
		issue.Title = "设备的通行范围与另一条连接重叠"
		issue.Detail = fmt.Sprintf("%s 的范围指向了另一条连接的专用地址（%s）："+
			"设备发往该网段的流量会被送进那条连接，而不是当前这条。", who, detail)
		issue.Fix = "把重叠的网段去掉，或把这台设备放到它真正要访问的那条连接下。"
	case hitScopeIsolate:
		issue.Title = "设备隔离与通行范围互相抵消"
		issue.Detail = fmt.Sprintf("%s 的范围含隧道网段 %s，但这条连接开了「设备之间互相隔离」："+
			"设备访问同隧道内其它设备的流量会被隔离规则丢弃。", who, detail)
		issue.Fix = "两者取一：要么关掉「设备之间互相隔离」，要么从通行范围里去掉隧道网段。"
	case hitScopeNeedsLAN:
		issue.Title = "设备允许访问家里内网，但这条连接没打开内网访问"
		issue.Detail = fmt.Sprintf("%s 的通行范围含家里网段，但连接的「允许设备访问家里内网」是关的："+
			"包能到达 NAS，却到不了家里的其它设备。", who)
		issue.Fix = "到「我的连接」把这条连接的「内网访问」开关打开；若本就不该访问内网，请改小设备的通行范围。"
	}
	return issue
}

// peerAddrsOutsideTunnel 判断一台设备的登记地址是否**全部**落在本连接隧道网段之外。
//
// 这类设备连不上，而且以前完全没有提示：地址一个都不在隧道网段里时，生成的配置会把它们
// 降级当成「可通过隧道访问的网段」，于是设备那份配置里带的是一个隧道外的地址 ——
// 握手能成，但本机没有回到那个地址的路由，回包被直接丢弃，现象只是「怎么都连不上」。
//
// 最容易踩到的路径：为了避免多台 NAS 默认网段撞车，把连接的「本机专用地址」改成了别的网段，
// 而这条连接下已有设备的地址没跟着改（它们仍留在旧网段里）。
func peerAddrsOutsideTunnel(it *model.Interface, p *model.Peer) bool {
	if len(it.Addresses) == 0 || len(p.AllowedIPs) == 0 {
		return false // 连接还没有地址时另有结论，不在这一条里重复报
	}
	subs := make([]*net.IPNet, 0, len(it.Addresses))
	for _, a := range it.Addresses {
		if _, n, err := net.ParseCIDR(strings.TrimSpace(a)); err == nil {
			subs = append(subs, n)
		}
	}
	if len(subs) == 0 {
		return false
	}
	for _, a := range p.AllowedIPs {
		ip, _, err := net.ParseCIDR(strings.TrimSpace(a))
		if err != nil {
			continue
		}
		for _, sn := range subs {
			if sn.Contains(ip) {
				return false
			}
		}
	}
	return true
}

// hasDefaultRoute 判断一组网段里是否含默认路由写法。
func hasDefaultRoute(scope []string) bool {
	for _, c := range scope {
		if wgback.IsDefaultRouteCIDR(c) {
			return true
		}
	}
	return false
}

// scopeOverlaps 返回 scope 中与 candidates 重叠的项，用于点名冲突对象。
func scopeOverlaps(scope, candidates []string) []string {
	hits := []string{}
	for _, a := range scope {
		_, an, err := net.ParseCIDR(strings.TrimSpace(a))
		if err != nil {
			continue
		}
		for _, b := range candidates {
			_, bn, err := net.ParseCIDR(strings.TrimSpace(b))
			if err != nil || bn == nil {
				continue
			}
			if cidrOverlap(an, bn) {
				if !containsString(hits, strings.TrimSpace(b)) {
					hits = append(hits, strings.TrimSpace(b))
				}
				break
			}
		}
	}
	sort.Strings(hits)
	return hits
}

// crossOverlaps 判断范围是否与其它连接的专用地址重叠。
func crossOverlaps(scope []string, others []model.Interface) bool {
	for i := range others {
		if len(scopeOverlaps(scope, cidrStrings(others[i].Addresses))) > 0 {
			return true
		}
	}
	return false
}

// crossDetail 生成「与哪条连接、哪个网段重叠」的具体说明。
func crossDetail(scope []string, others []model.Interface) string {
	parts := []string{}
	for i := range others {
		if hit := scopeOverlaps(scope, cidrStrings(others[i].Addresses)); len(hit) > 0 {
			parts = append(parts, fmt.Sprintf("%s 的 %s", others[i].Name, strings.Join(hit, "、")))
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, "；")
}

// peerListText 把设备名列表写成「「手机」「平板」等 3 台」这样的可读文本。
func peerListText(names []string) string {
	const show = 3
	quoted := make([]string, 0, show)
	for i, n := range names {
		if i >= show {
			break
		}
		quoted = append(quoted, "「"+n+"」")
	}
	text := strings.Join(quoted, "")
	if len(names) > show {
		text += fmt.Sprintf(" 等 %d 台设备", len(names))
	}
	return text
}

func displayPeerName(p *model.Peer) string {
	if strings.TrimSpace(p.Name) == "" {
		return "未命名设备"
	}
	return p.Name
}

// cidrStrings 过滤出合法的网段写法，并归一化成网络地址。
//
// 归一化是必须的：连接上存的是 10.10.0.1/24（主机写法），
// 而设备的通行范围里写的是 10.10.0.0/24（网段写法）。不归一化时，
// 结论里会把同一个网段的两种写法当成两个不同的东西展示给用户。
func cidrStrings(list []string) []string {
	out := []string{}
	for _, v := range list {
		if _, n, err := net.ParseCIDR(strings.TrimSpace(v)); err == nil {
			out = append(out, (&net.IPNet{IP: n.IP.Mask(n.Mask), Mask: n.Mask}).String())
		}
	}
	return out
}

func containsString(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
