package service

import (
	"context"
	"fmt"
	"net"
	"strings"

	"fnwg/internal/model"
)

func orEmptyStrings(list []string) []string {
	if list == nil {
		return []string{}
	}
	return list
}

func orEmptyRoutes(list []model.DefaultRoute) []model.DefaultRoute {
	if list == nil {
		return []model.DefaultRoute{}
	}
	return list
}

func orEmptyForeign(list []model.ForeignInterface) []model.ForeignInterface {
	if list == nil {
		return []model.ForeignInterface{}
	}
	return list
}

// NetworkCheckResult 是网络自检结果（面向用户的可读形式）。
type NetworkCheckResult struct {
	// Healthy 表示未发现任何影响 NAS 系统网络的问题。
	Healthy bool `json:"healthy"`
	// RouteInfoReadable 表示能否读取真实路由表（演示模式为 false）。
	RouteInfoReadable bool `json:"route_info_readable"`
	// ManagedInterfaces 本应用创建过的连接（网卡）。
	ManagedInterfaces []string `json:"managed_interfaces"`
	// SystemDefaults 系统自己的上网路线（应指向主网卡）。
	SystemDefaults []model.DefaultRoute `json:"system_defaults"`
	// StrayDefaults 本应用造成的异常上网路线（应被清除）。
	StrayDefaults []model.DefaultRoute `json:"stray_defaults"`
	// ForeignInterfaces 内核里存在、但不属于本应用的 WireGuard 网卡。
	// 可能是历史残留，也可能是用户用 wg-quick 等工具手工创建的。
	ForeignInterfaces []model.ForeignInterface `json:"foreign_interfaces"`
	// NAT 内网访问（设备访问家里其它机器）的规则状态。
	NAT model.NATStatus `json:"nat"`
	// ForwardPolicyDrop 系统转发链策略是否为丢弃（装过 Docker 的机器常见）。
	ForwardPolicyDrop bool `json:"forward_policy_drop"`
	// HomeSubnets 是探测到的 NAS 所在局域网网段。
	//
	// 暴露给界面是为了让「按设备划分访问范围」能直接给出可选项：
	// 让用户凭记忆手写家里网段，写错的概率远高于点一下。
	HomeSubnets []string `json:"home_subnets"`
	// AccessIssues 是「设备通行范围 / 内网访问 / 设备隔离」之间互相矛盾的结论。
	AccessIssues []AccessIssue `json:"access_issues"`
	// Messages 面向用户的结论说明。
	Messages []string `json:"messages"`
}

// orEmptyAccessIssues 归一化为空数组，避免前端拿到 null 后遍历报错。
func orEmptyAccessIssues(list []AccessIssue) []AccessIssue {
	if list == nil {
		return []AccessIssue{}
	}
	return list
}

// CheckNetwork 执行只读自检，不修改任何设置。
func (s *Service) CheckNetwork(ctx context.Context) (*NetworkCheckResult, error) {
	rep, err := s.Core.InspectNetwork(ctx)
	if err != nil {
		return nil, err
	}
	// 统一把 nil 切片归一化为空数组，避免前端拿到 null
	res := &NetworkCheckResult{
		Healthy:           len(rep.StrayDefaults) == 0,
		ManagedInterfaces: orEmptyStrings(rep.ManagedInterfaces),
		SystemDefaults:    orEmptyRoutes(rep.Defaults),
		StrayDefaults:     orEmptyRoutes(rep.StrayDefaults),
		ForeignInterfaces: orEmptyForeign(rep.ForeignInterfaces),
		NAT:               rep.NAT,
		ForwardPolicyDrop: rep.ForwardPolicyDrop,
		HomeSubnets:       orEmptyStrings(s.homeLANSubnets(ctx)),
		AccessIssues:      orEmptyAccessIssues(s.DiagnoseAccess(ctx)),
	}
	if res.NAT.Sources == nil {
		res.NAT.Sources = []string{}
	}
	if res.NAT.WANs == nil {
		res.NAT.WANs = []string{}
	}
	res.RouteInfoReadable = rep.RouteInfoReadable
	if len(rep.ManagedInterfaces) == 0 {
		res.Messages = append(res.Messages, "本应用尚未创建任何连接，不会对系统网络产生任何影响。")
	} else {
		res.Messages = append(res.Messages,
			fmt.Sprintf("本应用创建了 %d 条连接（%s），这些连接不会修改 NAS 自身的上网路线。",
				len(rep.ManagedInterfaces), strings.Join(rep.ManagedInterfaces, "、")))
	}
	// 疑似残留网卡：只提示，绝不自动处理 —— 它们也可能是用户用其它工具建的
	if len(rep.ForeignInterfaces) > 0 {
		names := make([]string, 0, len(rep.ForeignInterfaces))
		for _, fi := range rep.ForeignInterfaces {
			item := fi.Name
			if fi.ListenPort > 0 {
				item += fmt.Sprintf("（占用端口 %d）", fi.ListenPort)
			}
			names = append(names, item)
		}
		res.Messages = append(res.Messages, fmt.Sprintf(
			"发现 %d 个不是本应用创建的 WireGuard 网卡：%s。"+
				"它们可能是早期版本卸载时没清理干净的残留，也可能是其它工具在用。"+
				"残留会一直占着 UDP 端口，导致新连接无法使用这些端口；确认无用后可在下方清理。",
			len(rep.ForeignInterfaces), strings.Join(names, "、")))
	}
	if len(rep.StrayDefaults) > 0 {
		for _, d := range rep.StrayDefaults {
			res.Messages = append(res.Messages, fmt.Sprintf(
				"发现异常：NAS 的默认上网路线被指向了 %s（由本应用早期版本造成）。请点击「立即修复」，修复后 FN Connect 等系统功能即可恢复。",
				d.Dev))
		}
	} else if rep.RouteInfoReadable && len(rep.Defaults) == 0 {
		res.Healthy = false
		res.Messages = append(res.Messages,
			"发现异常：NAS 当前没有任何可用的默认上网路线，请到系统「网络设置」中重新保存一次网卡配置。")
	} else if !rep.RouteInfoReadable {
		res.Messages = append(res.Messages,
			"当前运行在演示模式，无法读取 NAS 的真实上网路线；在 fnOS 上运行时会显示实际检查结果。")
	} else {
		for _, d := range rep.Defaults {
			gw := d.Gw
			if gw == "" {
				gw = "（无网关）"
			}
			res.Messages = append(res.Messages, fmt.Sprintf("NAS 上网路线正常：经由 %s（网关 %s）。", d.Dev, gw))
		}
	}

	// 内网访问：设备能否访问 NAS 所在局域网中的其它设备
	if rep.NAT.Active {
		via := ""
		if len(res.NAT.WANs) > 0 {
			via = fmt.Sprintf("（经 %s 转发，已做源地址改写）", strings.Join(res.NAT.WANs, "、"))
		}
		res.Messages = append(res.Messages, fmt.Sprintf(
			"内网访问已开启：%s 的设备可以访问 NAS 所在局域网中的其它设备%s。",
			strings.Join(res.NAT.Sources, "、"), via))
		if rep.ForwardPolicyDrop {
			res.Messages = append(res.Messages,
				"检测到系统转发策略为「丢弃」（装过 Docker 的机器上很常见），"+
					"本应用已在系统转发链中为上述网段单独放行了一条规则；关闭内网访问时会自动移除。")
		}
	} else if res.NAT.Note != "" {
		res.Messages = append(res.Messages, "内网访问异常："+res.NAT.Note)
	}
	// 有设备却没开内网访问：这是「连上了但访问不了家里其它机器」最常见的成因
	if off := s.interfacesWithoutLanAccess(ctx); len(off) > 0 {
		res.Messages = append(res.Messages, fmt.Sprintf(
			"「%s」没有开启「允许设备访问家里内网」：连进来的设备只能访问 NAS 本身，"+
				"访问不了家里其它设备。需要的话到「我的连接」打开该连接的开关。",
			strings.Join(off, "」、「")))
	}
	// 逐层诊断：把「访问不了家里其它设备」定位到具体环节。
	// 网络层由数据面后端算出，这里把应用层的两项排在最前面。
	res.NAT.Checks = append(s.appNATChecks(ctx), res.NAT.Checks...)
	return res, nil
}

// appNATChecks 生成内网访问链路中「应用层」的两项自检：
// 开关是否打开、以及设备配置里的通行范围是否包含家里网段。
//
// 网络层的四项（转发规则 / 内核转发 / 系统转发链 / 出口网卡）由数据面后端
// 一并算出（见 wgback.natChecksLocked），这里只补应用层，并排在最前面。
func (s *Service) appNATChecks(ctx context.Context) []model.NATCheck {
	checks := []model.NATCheck{}
	ifaces, err := s.Store.ListInterfaces(ctx)
	if err != nil {
		return checks
	}

	on := []model.Interface{}
	all := []string{}
	for _, it := range ifaces {
		if !it.Enabled {
			continue
		}
		all = append(all, it.Name)
		if it.AllowLAN {
			on = append(on, it)
		}
	}
	if len(on) == 0 {
		detail := "本应用还没有创建连接"
		fix := ""
		if len(all) > 0 {
			detail = fmt.Sprintf("已启用的连接「%s」都没有打开这个开关", strings.Join(all, "」、「"))
			fix = "到「我的连接」把对应连接的「内网访问」开关打开"
		}
		return append(checks, model.NATCheck{
			Key: "switch", Label: "内网访问开关", OK: false, Detail: detail, Fix: fix,
		})
	}
	onNames := make([]string, 0, len(on))
	for _, it := range on {
		onNames = append(onNames, it.Name)
	}
	checks = append(checks, model.NATCheck{
		Key: "switch", Label: "内网访问开关", OK: true,
		Detail: fmt.Sprintf("「%s」已开启", strings.Join(onNames, "」、「")),
	})

	home := s.homeLANSubnets(ctx)
	clientOK, clientDetail := s.checkClientAllowedIPs(ctx, on, home)
	return append(checks, model.NATCheck{
		Key: "client_ips", Label: "设备的通行范围", OK: clientOK, Detail: clientDetail,
		Fix: "到「我的设备」重新生成该设备的二维码，用新配置重新导入设备",
	})
}

// checkClientAllowedIPs 检查设备的「通行范围」里是否真的包含家里网段。
// 不含的话包根本没送进隧道 —— 现象同样是「访问不了家里其它设备」。
func (s *Service) checkClientAllowedIPs(ctx context.Context, ifaces []model.Interface, home []string) (bool, string) {
	if len(home) == 0 {
		return false, "没有探测到 NAS 所在的局域网网段，请到「系统设置」手动指定家里网段"
	}
	for i := range ifaces {
		it := &ifaces[i]
		peers, err := s.Store.ListPeers(ctx, it.ID)
		if err != nil {
			continue
		}
		for j := range peers {
			p := &peers[j]
			if !p.Enabled {
				continue
			}
			if p.RouteMode == model.RouteModeFull {
				return true, fmt.Sprintf("设备「%s」使用「在外上网也走家里」，所有流量都经隧道，已覆盖家里网段", describePeer(p))
			}
			allowed := s.clientAllowedIPs(ctx, it, p, nil)
			if cidrCoversAll(allowed, home) {
				return true, fmt.Sprintf("设备「%s」的通行范围 %s 已包含家里网段 %s",
					describePeer(p), strings.Join(allowed, "、"), strings.Join(home, "、"))
			}
			return false, fmt.Sprintf(
				"设备「%s」的通行范围是 %s，不含家里网段 %s —— 设备根本不会把访问家里其它设备的流量送进隧道",
				describePeer(p), strings.Join(allowed, "、"), strings.Join(home, "、"))
		}
	}
	return false, "这些连接下还没有已启用的设备，先在「我的设备」里添加一台并重新生成二维码"
}

func describePeer(p *model.Peer) string {
	if strings.TrimSpace(p.Name) != "" {
		return p.Name
	}
	return fmt.Sprintf("#%d", p.ID)
}

// cidrCoversAll 判断 allowed 里的网段是否已完整覆盖 home 里的每个网段。
func cidrCoversAll(allowed, home []string) bool {
	nets := make([]*net.IPNet, 0, len(allowed))
	for _, s := range allowed {
		if _, n, err := net.ParseCIDR(strings.TrimSpace(s)); err == nil {
			nets = append(nets, n)
		}
	}
	for _, h := range home {
		_, hn, err := net.ParseCIDR(strings.TrimSpace(h))
		if err != nil {
			continue
		}
		covered := false
		for _, n := range nets {
			if (n.IP.To4() == nil) != (hn.IP.To4() == nil) {
				continue
			}
			no, _ := n.Mask.Size()
			ho, _ := hn.Mask.Size()
			if no <= ho && n.Contains(hn.IP) {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

// interfacesWithoutLanAccess 返回「已启用、有可用设备、但没开内网访问」的连接名。
func (s *Service) interfacesWithoutLanAccess(ctx context.Context) []string {
	ifaces, err := s.Store.ListInterfaces(ctx)
	if err != nil {
		return nil
	}
	out := []string{}
	for _, it := range ifaces {
		if !it.Enabled || it.AllowLAN {
			continue
		}
		peers, err := s.Store.ListPeers(ctx, it.ID)
		if err != nil {
			continue
		}
		for _, p := range peers {
			if p.Enabled {
				out = append(out, it.Name)
				break
			}
		}
	}
	return out
}

// RepairNetwork 清除本应用造成的网络残留（不会影响系统自身的任何设置）。
func (s *Service) RepairNetwork(ctx context.Context, a Actor) ([]string, error) {
	actions, err := s.Core.RepairNetwork(ctx)
	if err != nil {
		s.audit(ctx, a, "net.repair", "system", "", "", "", "error", err.Error())
		return actions, err
	}
	s.audit(ctx, a, "net.repair", "system", "", "", fmt.Sprint(len(actions)), "ok", strings.Join(actions, "; "))
	_ = s.Store.AddLog(ctx, "warn", "netguard", "执行网络自检修复", strings.Join(actions, "; "))
	return actions, nil
}

// CleanupNetwork 删除本应用创建的全部内核对象（供「停用」与「卸载」使用）。
func (s *Service) CleanupNetwork(ctx context.Context, a Actor) ([]string, error) {
	actions, err := s.Core.CleanupNetwork(ctx)
	if err != nil {
		return actions, err
	}
	s.audit(ctx, a, "net.cleanup", "system", "", "", fmt.Sprint(len(actions)), "ok", strings.Join(actions, "; "))
	return actions, nil
}

// DeleteForeignInterface 清理一个疑似残留的 WireGuard 网卡。
//
// 这是本应用唯一能删除「非自己创建」对象的能力，因此要求调用方原样传入
// 网卡名作为二次确认（界面会让用户手工输入）；数据面后端还会再次校验
// 该网卡的 link 类型必须是 wireguard，普通网卡一律拒绝。
func (s *Service) DeleteForeignInterface(ctx context.Context, name, confirm string, a Actor) ([]string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("请指定要清理的网卡名称")
	}
	if strings.TrimSpace(confirm) != name {
		return nil, fmt.Errorf("确认名称不一致：请输入「%s」以确认删除", name)
	}
	actions, err := s.Core.DeleteForeignInterface(ctx, name)
	if err != nil {
		s.audit(ctx, a, "net.delete_foreign", "interface", name, name, "", "error", err.Error())
		return actions, err
	}
	s.audit(ctx, a, "net.delete_foreign", "interface", name, name, "", "ok", strings.Join(actions, "; "))
	_ = s.Store.AddLog(ctx, "warn", "netguard", "清理疑似残留网卡 "+name, strings.Join(actions, "; "))
	return actions, nil
}
