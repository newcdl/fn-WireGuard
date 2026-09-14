//go:build linux

package wgback

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"fnwg/internal/model"
)

// 铁规则（任何改动都必须遵守）：
//  1. 只操作本应用自己创建过的内核对象（由 State.ManagedInterfaces 界定）；
//  2. 绝不创建、修改或删除系统默认路由；
//  3. 绝不覆盖系统上已存在的任何路由，只做「新增」；
//  4. 任何一步失败都只记录并跳过，不中断、不回滚系统状态。

type kernelBackend struct {
	mu     sync.Mutex
	client *wgctrl.Client
	state  *State
}

// New 创建内核态后端。statePath 用于记录受管对象与系统路由基线。
func New(statePath string) Backend {
	return &kernelBackend{state: LoadState(statePath)}
}

func (b *kernelBackend) Kind() string { return "kernel" }

func (b *kernelBackend) Caps() Capabilities {
	caps := Capabilities{Backend: "kernel"}
	if _, err := os.Stat("/sys/module/wireguard"); err == nil {
		caps.KernelModule = true
	} else if probeWireGuard() {
		caps.KernelModule = true
	}
	if _, err := os.Stat("/dev/net/tun"); err == nil {
		caps.TunDevice = true
	}
	return caps
}

// ManagedInterfaces 返回本应用创建过的接口名。
func (b *kernelBackend) ManagedInterfaces() []string { return b.state.ManagedCopy() }

// probeWireGuard 建立一次性 netlink 连接探测 WireGuard 内核支持是否可用。
func probeWireGuard() bool {
	c, err := wgctrl.New()
	if err != nil {
		return false
	}
	defer c.Close()
	_, err = c.Devices()
	return err == nil
}

func (b *kernelBackend) conn() (*wgctrl.Client, error) {
	if b.client != nil {
		return b.client, nil
	}
	c, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("连接 WireGuard 内核接口失败（请确认内核模块已加载且进程拥有 CAP_NET_ADMIN）: %w", err)
	}
	b.client = c
	return c, nil
}

func (b *kernelBackend) reset() {
	if b.client != nil {
		_ = b.client.Close()
		b.client = nil
	}
}

// Apply 执行期望态收敛。
func (b *kernelBackend) Apply(specs []model.InterfaceSpec, opts ApplyOptions) (Diff, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	var diff Diff
	client, err := b.conn()
	if err != nil {
		return diff, err
	}

	// 每次下发前先记录系统默认路由基线，并清除可能残留的危险路由。
	b.captureBaselineLocked()
	if actions, err := b.healLocked(); err == nil {
		for _, a := range actions {
			diff.Append("%s", a)
		}
	}

	managed := map[string]bool{}
	for _, spec := range specs {
		managed[spec.Name] = true
		if err := b.ensureOne(client, spec, opts, &diff); err != nil {
			b.reset()
			return diff, fmt.Errorf("接口 %s 收敛失败: %w", spec.Name, err)
		}
	}

	if opts.RemoveMissing {
		for _, name := range b.state.ManagedCopy() {
			if managed[name] {
				continue
			}
			diff.Append("删除多余接口 %s", name)
			if !opts.DryRun {
				if err := b.deleteLocked(name); err != nil {
					return diff, err
				}
			}
		}
	}
	return diff, nil
}

func (b *kernelBackend) ensureOne(client *wgctrl.Client, spec model.InterfaceSpec, opts ApplyOptions, diff *Diff) error {
	link, err := netlink.LinkByName(spec.Name)
	if err != nil {
		var notFound netlink.LinkNotFoundError
		if !errors.As(err, &notFound) {
			return err
		}
		link = nil
	}

	// 铁规则 1：同名设备已存在但不是本应用创建的 → 拒绝接管，绝不改写别人的配置。
	if link != nil && !b.state.IsManaged(spec.Name) {
		return fmt.Errorf("系统上已存在名为 %s 的网卡，但它不是本应用创建的。"+
			"为安全起见本应用不会接管它（可能是系统功能或其他应用正在使用），请改用其他名称（例如 wg7）", spec.Name)
	}

	if link == nil {
		diff.Append("创建 WireGuard 接口 %s", spec.Name)
		if opts.DryRun {
			return nil
		}
		attrs := netlink.LinkAttrs{Name: spec.Name}
		if spec.MTU > 0 {
			attrs.MTU = spec.MTU
		}
		if err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: attrs}); err != nil {
			return fmt.Errorf("创建接口失败: %w", err)
		}
		b.state.MarkManaged(spec.Name)
		_ = b.state.Save()
		link, err = netlink.LinkByName(spec.Name)
		if err != nil {
			return err
		}
	}

	// MTU
	if spec.MTU > 0 && link.Attrs().MTU != spec.MTU {
		diff.Append("设置 %s MTU=%d", spec.Name, spec.MTU)
		if !opts.DryRun {
			if err := netlink.LinkSetMTU(link, spec.MTU); err != nil {
				return err
			}
		}
	}

	// 接口与节点配置（ReplacePeers 保证节点集合与期望态严格一致）
	cfg := wgtypes.Config{ReplacePeers: true}
	if spec.PrivateKey != "" {
		k, err := wgtypes.ParseKey(spec.PrivateKey)
		if err != nil {
			return fmt.Errorf("接口私钥非法: %w", err)
		}
		cfg.PrivateKey = &k
	}
	if spec.ListenPort > 0 {
		p := spec.ListenPort
		cfg.ListenPort = &p
	}
	fm := spec.FWMark
	cfg.FirewallMark = &fm

	peers := make([]wgtypes.PeerConfig, 0, len(spec.Peers))
	for _, p := range spec.Peers {
		pk, err := wgtypes.ParseKey(p.PublicKey)
		if err != nil {
			return fmt.Errorf("节点公钥非法: %w", err)
		}
		pc := wgtypes.PeerConfig{PublicKey: pk, ReplaceAllowedIPs: true}
		if p.PresharedKey != "" {
			psk, err := wgtypes.ParseKey(p.PresharedKey)
			if err != nil {
				return fmt.Errorf("预共享密钥非法: %w", err)
			}
			pc.PresharedKey = &psk
		}
		if p.Endpoint != "" {
			if u, err := net.ResolveUDPAddr("udp", p.Endpoint); err == nil {
				pc.Endpoint = u
			}
		}
		if p.Keepalive > 0 {
			d := time.Duration(p.Keepalive) * time.Second
			pc.PersistentKeepaliveInterval = &d
		}
		for _, cidr := range p.AllowedIPs {
			ip, ipnet, err := net.ParseCIDR(cidr)
			if err != nil {
				return fmt.Errorf("AllowedIPs %q 非法: %w", cidr, err)
			}
			ipnet.IP = ip
			pc.AllowedIPs = append(pc.AllowedIPs, *ipnet)
		}
		peers = append(peers, pc)
	}
	cfg.Peers = peers
	if !opts.DryRun {
		if err := client.ConfigureDevice(spec.Name, cfg); err != nil {
			return fmt.Errorf("下发配置失败: %w", err)
		}
	}
	diff.Append("同步 %s 的 %d 个节点", spec.Name, len(peers))

	// 地址
	want, protected, err := parseAddrs(spec.Addresses)
	if err != nil {
		return err
	}
	if err := b.syncAddrs(link, want, opts, diff); err != nil {
		return err
	}

	// 路由：默认不管理（铁规则 2/3 由 PlanRoutes 保证）
	b.syncRoutes(link, spec, protected, opts, diff)

	// 起停
	isUp := link.Attrs().Flags&net.FlagUp != 0
	if spec.Up && !isUp {
		diff.Append("启用接口 %s", spec.Name)
		if !opts.DryRun {
			if err := netlink.LinkSetUp(link); err != nil {
				return err
			}
		}
	} else if !spec.Up && isUp {
		diff.Append("停用接口 %s", spec.Name)
		if !opts.DryRun {
			if err := netlink.LinkSetDown(link); err != nil {
				return err
			}
		}
	}
	return nil
}

// parseAddrs 把字符串地址转成 net.IPNet，并返回「受保护的网段」（接口自身网段）。
func parseAddrs(in []string) (want map[string]*net.IPNet, protected []*net.IPNet, err error) {
	want = map[string]*net.IPNet{}
	for _, cidr := range normAddrs(in) {
		ip, ipnet, e := net.ParseCIDR(cidr)
		if e != nil {
			return nil, nil, fmt.Errorf("接口地址 %q 非法: %w", cidr, e)
		}
		ipnet.IP = ip
		want[ipnet.String()] = ipnet
		masked := &net.IPNet{IP: ipnet.IP.Mask(ipnet.Mask), Mask: ipnet.Mask}
		protected = append(protected, masked)
	}
	return want, protected, nil
}

func (b *kernelBackend) syncAddrs(link netlink.Link, want map[string]*net.IPNet, opts ApplyOptions, diff *Diff) error {
	current, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	owned := map[string]bool{}
	for _, a := range current {
		if a.IPNet == nil {
			continue
		}
		owned[a.IPNet.String()] = true
	}
	for cidr, ipnet := range want {
		if owned[cidr] {
			continue
		}
		diff.Append("添加地址 %s → %s", cidr, link.Attrs().Name)
		if !opts.DryRun {
			if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: ipnet}); err != nil {
				return fmt.Errorf("添加地址 %s 失败: %w", cidr, err)
			}
		}
	}
	for _, a := range current {
		if a.IPNet == nil || a.IPNet.IP.IsLinkLocalUnicast() {
			continue
		}
		s := a.IPNet.String()
		if want[s] != nil {
			continue
		}
		diff.Append("移除地址 %s ← %s", s, link.Attrs().Name)
		if !opts.DryRun {
			del := a
			del.Peer = nil
			if err := netlink.AddrDel(link, &del); err != nil {
				return fmt.Errorf("移除地址 %s 失败: %w", s, err)
			}
		}
	}
	return nil
}

// syncRoutes 只做「新增」：是否新增、能新增哪些，全部由 PlanRoutes 决定。
// 本函数不会修改或删除系统上的任何既有路由。
func (b *kernelBackend) syncRoutes(link netlink.Link, spec model.InterfaceSpec, protected []*net.IPNet,
	opts ApplyOptions, diff *Diff) {

	idx := link.Attrs().Index
	allowedIPs := make([]string, 0, len(spec.Peers))
	for _, p := range spec.Peers {
		allowedIPs = append(allowedIPs, p.AllowedIPs...)
	}

	hostNets, existing, err := b.hostRouteContext(idx)
	if err != nil {
		diff.Append("读取系统路由失败，已跳过路由下发：%v", err)
		return
	}
	hostNets = append(hostNets, cidrStrings(protected)...)

	plan := PlanRoutes(RoutePlanInput{
		ManageRoutes:   spec.RouteTable == model.RouteTableClient,
		InterfaceName:  spec.Name,
		InterfaceIndex: idx,
		InterfaceAddrs: spec.Addresses,
		PeerAllowedIPs: allowedIPs,
		HostNetworks:   hostNets,
		ExistingRoutes: existing,
	})

	if !opts.DryRun {
		for _, cidr := range plan.Add {
			_, ipnet, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			r := &netlink.Route{
				LinkIndex: idx,
				Dst:       ipnet,
				Scope:     netlink.SCOPE_LINK,
				Family:    familyOf(ipnet.IP),
			}
			// 铁规则 3：只用 RouteAdd（已存在会失败），绝不用 RouteReplace 覆盖系统路由。
			if err := netlink.RouteAdd(r); err != nil {
				diff.Append("跳过路由 %s：%v", cidr, err)
				continue
			}
			diff.Append("添加路由 %s dev %s", cidr, spec.Name)
		}
	}
	if msg := DescribeSkip(plan.Skip); msg != "" {
		diff.Append("为保护 NAS 系统网络，以下网段未添加路由：%s", msg)
	}
}

// hostRouteContext 收集主机上（排除本接口）的网段与既有路由。
func (b *kernelBackend) hostRouteContext(excludeIdx int) ([]string, []HostRoute, error) {
	nets := []string{}
	links, err := netlink.LinkList()
	if err != nil {
		return nil, nil, err
	}
	for _, l := range links {
		if l.Attrs().Index == excludeIdx {
			continue
		}
		addrs, err := netlink.AddrList(l, netlink.FAMILY_ALL)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if a.IPNet == nil || a.IPNet.IP.IsLinkLocalUnicast() {
				continue
			}
			nets = append(nets, maskedCIDR(a.IPNet))
		}
	}

	routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return nets, nil, err
	}
	out := make([]HostRoute, 0, len(routes))
	for _, r := range routes {
		if r.LinkIndex == excludeIdx {
			continue
		}
		dst := ""
		if r.Dst != nil {
			dst = r.Dst.String()
			nets = append(nets, maskedCIDR(r.Dst))
		}
		out = append(out, HostRoute{Dst: dst, LinkIndex: r.LinkIndex, HasGw: r.Gw != nil, Family: r.Family})
	}
	return nets, out, nil
}

func maskedCIDR(n *net.IPNet) string {
	if n == nil {
		return ""
	}
	return (&net.IPNet{IP: n.IP.Mask(n.Mask), Mask: n.Mask}).String()
}

func cidrStrings(list []*net.IPNet) []string {
	out := make([]string, 0, len(list))
	for _, n := range list {
		if n != nil {
			out = append(out, n.String())
		}
	}
	return out
}

func covered(protected []*net.IPNet, ip net.IP) bool {
	for _, n := range protected {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func familyOf(ip net.IP) int {
	if ip.To4() != nil {
		return netlink.FAMILY_V4
	}
	return netlink.FAMILY_V6
}

// captureBaselineLocked 记录系统默认路由基线（仅首次，避免被污染后的状态覆盖）。
func (b *kernelBackend) captureBaselineLocked() {
	if b.state.BaselineTaken {
		return
	}
	var list []BaselineRoute
	if routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL); err == nil {
		for _, r := range routes {
			if r.Dst != nil || r.Gw == nil {
				continue
			}
			dev := ""
			if l, err := netlink.LinkByIndex(r.LinkIndex); err == nil {
				dev = l.Attrs().Name
			}
			fam := netlink.FAMILY_V4
			if r.Family == netlink.FAMILY_V6 {
				fam = netlink.FAMILY_V6
			}
			list = append(list, BaselineRoute{
				Family: fam, Gw: r.Gw.String(), Dev: dev, Metric: r.Priority, Table: r.Table,
			})
		}
	}
	b.state.SetBaseline(list)
	_ = b.state.Save()
}

// Heal 清除指向本应用接口的异常默认路由，并在必要时恢复系统默认路由。
// 这是「重装/升级也不会再把 NAS 网络弄坏」的关键保障。
func (b *kernelBackend) Heal(ctx context.Context) ([]string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.captureBaselineLocked()
	return b.healLocked()
}

func (b *kernelBackend) healLocked() ([]string, error) {
	var actions []string

	managed := map[int]string{}
	for _, name := range b.state.ManagedCopy() {
		if l, err := netlink.LinkByName(name); err == nil {
			managed[l.Attrs().Index] = name
		} else {
			// 接口已不存在，清理记录
			b.state.UnmarkManaged(name)
		}
	}
	if err := b.state.Save(); err != nil {
		actions = append(actions, fmt.Sprintf("保存安全状态失败：%v", err))
	}
	if len(managed) == 0 {
		return actions, nil
	}

	routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return actions, err
	}
	removed := false
	for _, r := range routes {
		if r.Dst != nil {
			continue // 只处理默认路由
		}
		name, ok := managed[r.LinkIndex]
		if !ok {
			continue
		}
		del := r
		if err := netlink.RouteDel(&del); err != nil {
			actions = append(actions, fmt.Sprintf("清除异常默认路由失败（dev=%s）：%v", name, err))
			continue
		}
		removed = true
		actions = append(actions, fmt.Sprintf(
			"已删除指向 %s 的异常默认路由：它曾抢占 NAS 自身的上网路线（这是影响 FN Connect 的根因）", name))
	}

	if removed && !b.hasForeignDefault(managed) {
		actions = append(actions, b.restoreBaselineLocked()...)
	}
	return actions, nil
}

// hasForeignDefault 判断系统是否还有一条由系统自己管理的默认路由。
func (b *kernelBackend) hasForeignDefault(managed map[int]string) bool {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return true // 读不到时不做任何恢复动作
	}
	for _, r := range routes {
		if r.Dst != nil {
			continue
		}
		if _, ours := managed[r.LinkIndex]; !ours {
			return true
		}
	}
	return false
}

// restoreBaselineLocked 按基线恢复系统默认路由。
func (b *kernelBackend) restoreBaselineLocked() []string {
	var actions []string
	for _, br := range b.state.Baseline() {
		if br.Gw == "" || br.Dev == "" {
			continue
		}
		link, err := netlink.LinkByName(br.Dev)
		if err != nil {
			continue
		}
		ip := net.ParseIP(br.Gw)
		if ip == nil {
			continue
		}
		r := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Gw:        ip,
			Priority:  br.Metric,
			Table:     br.Table,
			Family:    br.Family,
		}
		if err := netlink.RouteAdd(r); err != nil {
			actions = append(actions, fmt.Sprintf("恢复系统默认路由失败（via %s dev %s）：%v", br.Gw, br.Dev, err))
			continue
		}
		actions = append(actions, fmt.Sprintf("已恢复 NAS 系统默认路由：via %s dev %s", br.Gw, br.Dev))
	}
	if len(actions) == 0 {
		actions = append(actions, "注意：NAS 当前没有可用的默认路由且无基线可恢复，请在系统「网络设置」中重新保存一次网卡配置")
	}
	return actions
}

// DeleteInterface 删除接口。
func (b *kernelBackend) DeleteInterface(name string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.deleteLocked(name)
}

func (b *kernelBackend) deleteLocked(name string) error {
	if !b.state.IsManaged(name) {
		// 铁规则 1：不删除不是自己创建的接口。
		return fmt.Errorf("接口 %s 不是本应用创建的，为避免影响系统功能已拒绝删除", name)
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		var notFound netlink.LinkNotFoundError
		if errors.As(err, &notFound) {
			b.state.UnmarkManaged(name)
			_ = b.state.Save()
			return nil
		}
		return err
	}
	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("删除接口 %s 失败: %w", name, err)
	}
	b.state.UnmarkManaged(name)
	_ = b.state.Save()
	return nil
}

// Cleanup 删除本应用创建的全部接口与残留路由（用于「停用」与「卸载」）。
func (b *kernelBackend) Cleanup(ctx context.Context) ([]string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	var actions []string
	for _, name := range b.state.ManagedCopy() {
		actions = append(actions, fmt.Sprintf("删除本应用创建的接口 %s", name))
		if err := b.deleteLocked(name); err != nil {
			actions = append(actions, fmt.Sprintf("删除接口 %s 失败：%v", name, err))
		}
	}
	healed, err := b.healLocked()
	actions = append(actions, healed...)
	if err != nil {
		return actions, err
	}
	b.reset()
	return actions, nil
}

// Snapshot 采集实时状态。
func (b *kernelBackend) Snapshot(names []string) ([]model.InterfaceStatus, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	client, err := b.conn()
	if err != nil {
		return nil, err
	}
	devs, err := client.Devices()
	if err != nil {
		b.reset()
		return nil, err
	}
	filter := map[string]bool{}
	for _, n := range names {
		filter[n] = true
	}

	out := make([]model.InterfaceStatus, 0, len(devs))
	for _, d := range devs {
		// 只汇报本应用创建的接口，避免把系统或其他应用的接口显示成自己的
		if !b.state.IsManaged(d.Name) {
			continue
		}
		if len(filter) > 0 && !filter[d.Name] {
			continue
		}
		st := model.InterfaceStatus{
			Name:       d.Name,
			PublicKey:  d.PublicKey.String(),
			ListenPort: d.ListenPort,
			FWMark:     d.FirewallMark,
			Peers:      make([]model.PeerStatus, 0, len(d.Peers)),
		}
		if link, err := netlink.LinkByName(d.Name); err == nil {
			st.Up = link.Attrs().Flags&net.FlagUp != 0
			st.MTU = link.Attrs().MTU
			if addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL); err == nil {
				for _, a := range addrs {
					if a.IPNet != nil && !a.IPNet.IP.IsLinkLocalUnicast() {
						st.Addresses = append(st.Addresses, a.IPNet.String())
					}
				}
			}
		}
		for _, p := range d.Peers {
			ps := model.PeerStatus{
				PublicKey:    p.PublicKey.String(),
				RxBytes:      p.ReceiveBytes,
				TxBytes:      p.TransmitBytes,
				PresharedKey: p.PresharedKey != wgtypes.Key{},
				Keepalive:    int(p.PersistentKeepaliveInterval.Seconds()),
			}
			if p.Endpoint != nil {
				ps.Endpoint = p.Endpoint.String()
			}
			if !p.LastHandshakeTime.IsZero() {
				ps.LastHandshake = p.LastHandshakeTime
			}
			for _, ipnet := range p.AllowedIPs {
				ps.AllowedIPs = append(ps.AllowedIPs, ipnet.String())
			}
			st.Peers = append(st.Peers, ps)
		}
		out = append(out, st)
	}
	return out, nil
}

// Inspect 供网络自检使用：返回本应用相关的事实，不做任何修改。
func (b *kernelBackend) Inspect(ctx context.Context) (model.NetworkReport, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	rep := model.NetworkReport{RouteInfoReadable: true, ManagedInterfaces: b.state.ManagedCopy()}
	managed := map[int]string{}
	for _, name := range rep.ManagedInterfaces {
		if l, err := netlink.LinkByName(name); err == nil {
			managed[l.Attrs().Index] = name
		}
	}
	routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return rep, err
	}
	for _, r := range routes {
		if r.Dst != nil {
			continue
		}
		entry := model.DefaultRoute{Family: r.Family, Metric: r.Priority, Table: r.Table}
		if r.Gw != nil {
			entry.Gw = r.Gw.String()
		}
		if l, err := netlink.LinkByIndex(r.LinkIndex); err == nil {
			entry.Dev = l.Attrs().Name
		}
		if name, ours := managed[r.LinkIndex]; ours {
			entry.OwnedByUs = true
			entry.Dev = name
			rep.StrayDefaults = append(rep.StrayDefaults, entry)
			continue
		}
		rep.Defaults = append(rep.Defaults, entry)
	}
	return rep, nil
}

var _ = strconv.Itoa
