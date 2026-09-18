// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 newcdl <newcdl@163.com>

//go:build linux

package wgback

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"fnwg/internal/model"
)

// 铁规则（任何改动都必须遵守）：
//  1. 只操作本应用自己创建过的内核对象（由 State.ManagedInterfaces 界定）；
//  2. 绝不创建、修改或删除系统默认路由；
//  3. 绝不覆盖系统上已存在的任何路由，只做「新增」；
//  4. 任何一步失败都只记录并跳过，不中断、不回滚系统状态。

type linuxBackend struct {
	mu     sync.Mutex
	driver wireGuardDriver
	state  *State
	// endpoints 缓存对端地址的 DNS 解析结果，见 resolveEndpoint。
	endpoints map[string]endpointEntry
	// fallback 是「自动回退」的备选驱动：内核模式在运行时被证实不可用时，
	// 就地切到它并重试一次，避免用户在「模块文件在、但加载被拒」的系统上完全用不了。
	// 一旦切换即置空，不会在两种实现之间来回横跳。
	fallback func() wireGuardDriver
	// kind 记录当前实际生效的后端标识（回退后会由 kernel 变为 userspace）。
	kind string
	// driverUsed 记录本轮收敛中当前驱动是否已经真正接管过设备。
	//
	// 它决定「运行时回退」还能不能发生：只要当前驱动已经建出/接管了设备，
	// 再回退就会留下「一部分连接走内核、一部分走用户态」的混合数据面 ——
	// 那种局面比直接报错更难排查，因此宁可让这一轮失败也不回退。
	driverUsed bool
}

// New 创建 Linux 数据面后端。statePath 用于记录受管对象与系统路由基线。
func New(statePath string) Backend {
	return newLinuxBackend(LoadState(statePath))
}

// newLinuxBackend 选择数据面驱动。
//
// 选择顺序：
//  1. 环境变量 FNWG_BACKEND 显式指定 kernel / userspace 时，直接照办 —— 这是运维
//     在自动判断出错时的逃生舱，因此绝不在其之上再自动切换；
//  2. 自动模式：内核具备能力就用内核（标准模式）；内核明显缺失但系统提供
//     /dev/net/tun 时直接使用用户态实现，不必先撞一次失败；
//  3. 内核「看起来可用」（模块文件在）但真正创建接口时才被拒的系统，
//     由 Apply 在运行时回退 —— 见 switchToFallback。
func newLinuxBackend(state *State) *linuxBackend {
	b := &linuxBackend{state: state, endpoints: map[string]endpointEntry{}}
	mode := strings.ToLower(strings.TrimSpace(os.Getenv(envBackendMode)))
	if mode == "" {
		mode = modeAuto
	}
	switch mode {
	case modeKernel:
		b.driver = newKernelDriver()
	case modeUserspace:
		b.driver = newUserspaceDriver()
	default: // modeAuto 或无法识别的取值：一律按自动处理，绝不让一个拼错的值把应用变成不可用
		switch {
		case kernelModuleAvailable():
			b.driver = newKernelDriver()
			if tunDeviceAvailable() {
				b.fallback = func() wireGuardDriver { return newUserspaceDriver() }
			}
		case tunDeviceAvailable():
			b.driver = newUserspaceDriver()
		default:
			// 两条路都没有：仍用内核驱动，让 Ready 报出「如何完成上电准备」的提示，
			// 比抛一句「无可用后端」更能让用户知道下一步该做什么。
			b.driver = newKernelDriver()
		}
	}
	b.kind = b.driver.Kind()
	return b
}

func (b *linuxBackend) Kind() string { return b.kind }

func (b *linuxBackend) Caps() Capabilities { return b.driver.Caps() }

// ManagedInterfaces 返回本应用创建过的接口名。
func (b *linuxBackend) ManagedInterfaces() []string { return b.state.ManagedCopy() }

// switchToFallback 切换到备选驱动，只在内核被证实不可用时调用。
//
// 安全性依据：内核是在「创建接口」这一步才被证实不可用的，此时本进程还没有
// 按内核模式建出任何网卡，因此不存在「一半内核、一半用户态」的混合状态。
func (b *linuxBackend) switchToFallback(cause error) {
	fb := b.fallback
	if fb == nil {
		return
	}
	b.fallback = nil
	b.driver.Reset()
	b.driver = fb()
	b.kind = b.driver.Kind()
	slog.Warn("内核 WireGuard 不可用，已切换为兼容模式（用户态实现）",
		"原因", cause, "说明", "吞吐略低于标准模式，功能不受影响")
}

// Apply 执行期望态收敛。
func (b *linuxBackend) Apply(specs []model.InterfaceSpec, opts ApplyOptions) (Diff, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	var diff Diff
	b.driverUsed = false
	if err := b.driver.Ready(); err != nil {
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
	var failures []string
	for _, spec := range specs {
		managed[spec.Name] = true
		err := b.ensureOne(spec, opts, &diff)
		// 内核在「创建接口」这一步才暴露「不支持」：此时就地回退并重试一次，
		// 而不是把用户卡在一条他自己无法修复的错误上。
		// 前提是本驱动还没接管过任何设备，否则会形成混合数据面（见 driverUsed）。
		if err != nil && b.fallback != nil && !b.driverUsed && errors.Is(err, errBackendUnsupported) {
			b.switchToFallback(err)
			err = b.ensureOne(spec, opts, &diff)
		}
		if err != nil {
			// 单条连接失败不阻断其余连接：否则系统里一个历史残留网卡
			// （例如上一版卸载时没清干净的 wg0）就能让所有连接都无法下发。
			failures = append(failures, fmt.Sprintf("%s：%v", spec.Name, err))
			b.driver.Reset()
			continue
		}
	}
	// 内网访问（NAT 转发）：按全部连接的期望态聚合，见 nat.go。
	// 与单条连接是否成功无关，因此放在失败检查之前。
	b.syncNATLocked(specs, opts, &diff)

	if len(failures) > 0 {
		return diff, fmt.Errorf("有 %d 条连接未能下发 —— %s", len(failures), strings.Join(failures, "；"))
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

func (b *linuxBackend) ensureOne(spec model.InterfaceSpec, opts ApplyOptions, diff *Diff) error {
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

	if link != nil {
		// 当前驱动已经在本进程里接管过这张网卡 —— 有它在，就说明本驱动是可用的，
		// 后续偶发失败不该触发回退（否则会把新连接甩到另一种实现上，形成混合数据面）。
		if b.state.InterfaceBackend(spec.Name) == b.kind {
			b.driverUsed = true
		}
		// 数据面实现变了（系统升级后内核模块可用、或反过来）：
		// 旧网卡是另一种实现创建的，当前驱动既读不到配置也配不上去。
		// 它是本应用自己的对象，删掉重建是唯一能让连接恢复工作的做法，且只影响自己。
		if prev := b.state.InterfaceBackend(spec.Name); prev != "" && prev != b.kind {
			diff.Append("重建 %s（数据面由%s切换为%s）", spec.Name, backendLabel(prev), backendLabel(b.kind))
			if opts.DryRun {
				return nil
			}
			b.clearPolicyRoutesLocked(spec.Name)
			if err := b.driver.Delete(spec.Name); err != nil {
				return fmt.Errorf("切换数据面时删除旧网卡 %s 失败: %w", spec.Name, err)
			}
			link = nil
		}
	}

	if link == nil {
		diff.Append("创建 WireGuard 接口 %s", spec.Name)
		if opts.DryRun {
			return nil
		}
		// 设备如何创建由驱动决定：内核模式走 rtnl 创建 wireguard 网卡，
		// 兼容模式走 TUN + 用户态实现。创建失败时若为「本内核不支持」，
		// 会以 errBackendUnsupported 上报，由 Apply 决定是否回退。
		created, err := b.driver.Ensure(spec.Name, spec.MTU)
		if err != nil {
			return err
		}
		b.driverUsed = true
		if created {
			b.state.MarkManaged(spec.Name)
		}
		// 无论是否新建，都记下创建者：新建时是新记录，重建时覆盖旧实现。
		b.state.SetInterfaceBackend(spec.Name, b.kind)
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

	// 设备与节点配置：按增量下发（见 peerdiff.go）。
	// 绝不再使用 ReplacePeers —— 内核收到它会执行 wg_peer_remove_all()，
	// 清空重建全部节点，销毁会话密钥与动态学习到的 endpoint。
	current, err := b.driver.Read(spec.Name)
	if err != nil {
		// 刚创建、或后端暂时读不到时，退化为「全部按新增处理」
		current = nil
	}
	if err := b.syncDevice(spec, current, opts, diff); err != nil {
		return err
	}

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

// ---------------------------------------------------------------- 设备与节点增量下发

// syncDevice 只下发与内核现状存在差异的部分。
//
// 这是「隧道不抖动」的关键：没有变化的节点与字段完全不进入下发请求，
// 内核因此不会重置它的会话密钥与动态学习到的 endpoint；
// 全部一致时连一次 ConfigureDevice 都不会调用。
func (b *linuxBackend) syncDevice(spec model.InterfaceSpec,
	current *wgtypes.Device, opts ApplyOptions, diff *Diff) error {

	cfg := wgtypes.Config{}
	var notes []string

	// 本机密钥：用公钥比较。内核在没有 CAP_NET_ADMIN 时不会回传私钥，
	// 但公钥始终可读，用它判断可以避免「每轮都重设私钥」。
	if spec.PrivateKey != "" {
		k, err := wgtypes.ParseKey(spec.PrivateKey)
		if err != nil {
			return fmt.Errorf("接口私钥非法: %w", err)
		}
		if current == nil || current.PublicKey != k.PublicKey() {
			cfg.PrivateKey = &k
			notes = append(notes, "本机密钥")
		}
	}
	// 服务端口：仅在变化时下发
	if spec.ListenPort > 0 && (current == nil || current.ListenPort != spec.ListenPort) {
		p := spec.ListenPort
		cfg.ListenPort = &p
		notes = append(notes, fmt.Sprintf("服务端口→%d", p))
	}
	// 防火墙标记：同样只在变化时下发（下发给 0 会清除已有标记）
	if current == nil || current.FirewallMark != spec.FWMark {
		cfg.FirewallMark = &spec.FWMark
		if spec.FWMark != 0 {
			notes = append(notes, fmt.Sprintf("防火墙标记→%d", spec.FWMark))
		}
	}

	want, err := b.peerWants(spec, diff)
	if err != nil {
		return err
	}
	changes := DiffPeers(want, peerHaves(current), b.pskNeedsPush(spec))

	added, updated, removed := 0, 0, 0
	for _, c := range changes {
		pc, err := b.toPeerConfig(spec, c)
		if err != nil {
			return err
		}
		cfg.Peers = append(cfg.Peers, pc)
		switch c.Kind {
		case PeerDiffAdd:
			added++
			diff.Append("新增节点 %s", peerLabel(spec, c.PublicKey))
		case PeerDiffUpdate:
			updated++
			diff.Append("更新节点 %s（%s）", peerLabel(spec, c.PublicKey), strings.Join(c.Fields, "、"))
		case PeerDiffRemove:
			removed++
			b.state.DropPskFingerprint(spec.Name, c.PublicKey)
			diff.Append("移除节点 %s", peerLabel(spec, c.PublicKey))
		}
	}

	if len(notes) == 0 && len(changes) == 0 {
		// 与内核完全一致：一次下发都不做，节点会话与流量统计保持原样
		return nil
	}
	if opts.DryRun {
		diff.Append("（预演）%s 需要下发：%s", spec.Name, describeChanges(notes, added, updated, removed))
		return nil
	}
	if err := b.driver.Configure(spec.Name, cfg); err != nil {
		return err
	}
	b.rememberPSKFingerprints(spec)
	diff.Append("已同步 %s（共 %d 个节点：新增 %d、更新 %d、移除 %d%s）",
		spec.Name, len(want), added, updated, removed, notesSuffix(notes))
	return nil
}

// peerWants 把期望态节点转成可比较形式，并带上解析后的对端地址。
func (b *linuxBackend) peerWants(spec model.InterfaceSpec, diff *Diff) ([]PeerWant, error) {
	out := make([]PeerWant, 0, len(spec.Peers))
	for _, p := range spec.Peers {
		if p.PublicKey == "" {
			continue
		}
		ep := ""
		if strings.TrimSpace(p.Endpoint) != "" {
			// 收敛每 10 秒一轮，解析结果必须缓存：
			// DNS 查询（尤其超时）会阻塞整轮收敛，表现为隧道延迟毛刺。
			addr, err := b.resolveEndpoint(p.Endpoint)
			if err != nil {
				diff.Append("解析对端地址 %s 失败，本次跳过该字段：%v", p.Endpoint, err)
			} else {
				ep = addr
			}
		}
		out = append(out, PeerWant{
			PublicKey:    p.PublicKey,
			Endpoint:     ep,
			AllowedIPs:   p.AllowedIPs,
			Keepalive:    p.Keepalive,
			HasPreshared: strings.TrimSpace(p.PresharedKey) != "",
		})
	}
	return out, nil
}

// peerHaves 把内核当前节点转成可比较形式。
func peerHaves(dev *wgtypes.Device) []PeerHave {
	if dev == nil {
		return nil
	}
	out := make([]PeerHave, 0, len(dev.Peers))
	for _, p := range dev.Peers {
		h := PeerHave{
			PublicKey:    p.PublicKey.String(),
			Keepalive:    int(p.PersistentKeepaliveInterval.Seconds()),
			HasPreshared: p.PresharedKey != wgtypes.Key{},
		}
		if p.Endpoint != nil {
			h.Endpoint = p.Endpoint.String()
		}
		for _, n := range p.AllowedIPs {
			h.AllowedIPs = append(h.AllowedIPs, n.String())
		}
		out = append(out, h)
	}
	return out
}

// toPeerConfig 把一个变更转换为内核下发结构。
func (b *linuxBackend) toPeerConfig(spec model.InterfaceSpec, c PeerDiff) (wgtypes.PeerConfig, error) {
	pk, err := wgtypes.ParseKey(c.PublicKey)
	if err != nil {
		return wgtypes.PeerConfig{}, fmt.Errorf("节点公钥非法: %w", err)
	}
	pc := wgtypes.PeerConfig{PublicKey: pk}

	if c.Kind == PeerDiffRemove {
		pc.Remove = true
		return pc, nil
	}
	if c.SetAllowedIPs {
		// ReplaceAllowedIPs 只替换通行范围，不会重置会话
		allowed, err := parseIPNets(c.AllowedIPs)
		if err != nil {
			return pc, err
		}
		pc.ReplaceAllowedIPs = true
		pc.AllowedIPs = allowed
	}
	if c.SetEndpoint {
		u, err := net.ResolveUDPAddr("udp", c.Endpoint)
		if err != nil {
			return pc, fmt.Errorf("对端地址 %q 非法: %w", c.Endpoint, err)
		}
		pc.Endpoint = u
	}
	if c.SetKeepalive {
		d := time.Duration(c.Keepalive) * time.Second
		pc.PersistentKeepaliveInterval = &d
	}
	if c.SetPresharedKey {
		if c.PresharedWanted {
			k, err := wgtypes.ParseKey(findPeerPSK(spec, c.PublicKey))
			if err != nil {
				return pc, fmt.Errorf("二次加密口令非法: %w", err)
			}
			pc.PresharedKey = &k
		} else {
			// 非 nil 的零值表示清除口令
			zero := wgtypes.Key{}
			pc.PresharedKey = &zero
		}
	}
	return pc, nil
}

// parseIPNets 把 CIDR 字符串转成 net.IPNet 列表。
func parseIPNets(list []string) ([]net.IPNet, error) {
	out := make([]net.IPNet, 0, len(list))
	for _, cidr := range list {
		ip, ipnet, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err != nil {
			return nil, fmt.Errorf("通行范围 %q 非法: %w", cidr, err)
		}
		ipnet.IP = ip
		out = append(out, *ipnet)
	}
	return out, nil
}

// pskNeedsPush 返回一个判断函数：该节点的二次加密口令是否需要重新下发。
//
// 内核不返回口令明文，只能靠本地指纹判断。两边都有口令且指纹一致时绝不重发，
// 因为重新下发口令会让内核 wg_noise_expire_current_peer_keypairs()
// 销毁该节点当前的会话密钥 —— 这正是早期版本「每轮重下发」造成掉线的另一个原因。
func (b *linuxBackend) pskNeedsPush(spec model.InterfaceSpec) func(string) bool {
	return func(publicKey string) bool {
		raw := findPeerPSK(spec, publicKey)
		if raw == "" {
			return false
		}
		return b.state.PskFingerprint(spec.Name, publicKey) != pskFingerprint(raw)
	}
}

// rememberPSKFingerprints 记录本次成功下发的口令指纹。
func (b *linuxBackend) rememberPSKFingerprints(spec model.InterfaceSpec) {
	changed := false
	for _, p := range spec.Peers {
		raw := strings.TrimSpace(p.PresharedKey)
		if p.PublicKey == "" || raw == "" {
			continue
		}
		fp := pskFingerprint(raw)
		if b.state.PskFingerprint(spec.Name, p.PublicKey) != fp {
			b.state.SetPskFingerprint(spec.Name, p.PublicKey, fp)
			changed = true
		}
	}
	if changed {
		_ = b.state.Save()
	}
}

// findPeerPSK 取出指定节点的二次加密口令明文。
func findPeerPSK(spec model.InterfaceSpec, publicKey string) string {
	for _, p := range spec.Peers {
		if p.PublicKey == publicKey {
			return strings.TrimSpace(p.PresharedKey)
		}
	}
	return ""
}

// peerLabel 返回便于阅读的节点标识（优先用名称）。
func peerLabel(spec model.InterfaceSpec, publicKey string) string {
	for _, p := range spec.Peers {
		if p.PublicKey != publicKey {
			continue
		}
		if strings.TrimSpace(p.Name) != "" {
			return fmt.Sprintf("%s（%s）", strings.TrimSpace(p.Name), shortKey(publicKey))
		}
		break
	}
	return shortKey(publicKey)
}

// shortKey 截取公钥前若干字符，便于在日志里辨认。
func shortKey(key string) string {
	if len(key) <= 12 {
		return key
	}
	return key[:12] + "…"
}

func describeChanges(notes []string, added, updated, removed int) string {
	parts := append([]string{}, notes...)
	if added > 0 {
		parts = append(parts, fmt.Sprintf("新增 %d 个节点", added))
	}
	if updated > 0 {
		parts = append(parts, fmt.Sprintf("更新 %d 个节点", updated))
	}
	if removed > 0 {
		parts = append(parts, fmt.Sprintf("移除 %d 个节点", removed))
	}
	if len(parts) == 0 {
		return "无"
	}
	return strings.Join(parts, "、")
}

func notesSuffix(notes []string) string {
	if len(notes) == 0 {
		return ""
	}
	return "，" + strings.Join(notes, "、")
}

// 对端地址解析结果的缓存时长。
//
// 收敛循环每 10 秒一轮；如果每轮都对域名做 DNS 查询，
// 一次超时（常见 3~5 秒）就会把整轮收敛拖住。
const (
	endpointTTL   = 5 * time.Minute
	endpointRetry = 30 * time.Second
)

type endpointEntry struct {
	addr    string
	expires time.Time
}

// resolveEndpoint 解析对端地址（IP 或域名 + 端口），结果带缓存。
func (b *linuxBackend) resolveEndpoint(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	now := time.Now()
	if e, ok := b.endpoints[raw]; ok && now.Before(e.expires) && e.addr != "" {
		return e.addr, nil
	}
	u, err := net.ResolveUDPAddr("udp", raw)
	if err != nil {
		// 解析失败时沿用上一次成功的地址：瞬时 DNS 故障不该把已配好的对端地址改坏。
		// 同时缩短重试间隔，DNS 恢复后能尽快跟进。
		if e, ok := b.endpoints[raw]; ok && e.addr != "" {
			b.endpoints[raw] = endpointEntry{addr: e.addr, expires: now.Add(endpointRetry)}
			return e.addr, nil
		}
		return "", err
	}
	addr := u.String()
	b.endpoints[raw] = endpointEntry{addr: addr, expires: now.Add(endpointTTL)}
	return addr, nil
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

func (b *linuxBackend) syncAddrs(link netlink.Link, want map[string]*net.IPNet, opts ApplyOptions, diff *Diff) error {
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

// syncRoutes 依据 PlanRoutes 的结论下发路由。
//
// 铁规则 2/3：绝不创建、修改或删除系统主路由表里的任何条目。
// 需要下发时（异地组网场景）一律写进本应用专用策略表并用 ip rule 限定目标网段，
// 详见 policyroute.go —— 系统主表在整个生命周期里零改动。
func (b *linuxBackend) syncRoutes(link netlink.Link, spec model.InterfaceSpec, protected []*net.IPNet,
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
	want := PlanPolicyRoutes(spec.Name, plan)

	if opts.DryRun {
		for _, pr := range want {
			diff.Append("将添加策略路由 %s dev %s（专用表 %d）", pr.CIDR, spec.Name, pr.Table)
		}
	} else {
		b.applyPolicyRoutesLocked(spec.Name, want, idx, diff)
	}
	if msg := DescribeSkip(plan.Skip); msg != "" {
		diff.Append("为保护 NAS 系统网络，以下网段未添加路由：%s", msg)
	}
}

// applyPolicyRoutesLocked 让某条连接的策略路由与期望态一致：补齐缺失的、清除多余的。
// 只处理状态文件里记录过的条目，绝不动别人的规则。
func (b *linuxBackend) applyPolicyRoutesLocked(dev string, want []PolicyRoute, linkIndex int, diff *Diff) {
	keep := make(map[string]bool, len(want))
	for _, pr := range want {
		keep[pr.CIDR] = true
	}
	// 先清理：连接关掉「异地组网」后，旧规则必须撤销，否则会一直对目标网段生效
	for _, pr := range b.state.PolicyRoutesFor(dev) {
		if keep[pr.CIDR] {
			continue
		}
		action, err := b.removePolicyRoute(pr)
		if err != nil {
			diff.Append("撤销策略路由 %s 失败：%v", pr.CIDR, err)
			continue
		}
		if action != "" {
			diff.Append("%s", action)
		}
	}
	// 再补齐
	for _, pr := range want {
		if b.state.HasPolicyRoute(dev, pr.CIDR) {
			continue
		}
		if err := b.addPolicyRoute(pr, linkIndex); err != nil {
			diff.Append("添加策略路由 %s 失败：%v", pr.CIDR, err)
			continue
		}
		b.state.MarkPolicyRoute(pr)
		diff.Append("添加策略路由 %s dev %s（专用表 %d，未改动系统主路由表）", pr.CIDR, dev, pr.Table)
	}
	_ = b.state.Save()
}

// addPolicyRoute 下发一条策略路由：先补 ip rule，再写专用表。
//
// 顺序很重要：没有规则指向该表时，表里的路由不会被任何流量查到。
// 先补规则可以保证不会出现「路由已写但规则缺失」的中间态。
func (b *linuxBackend) addPolicyRoute(pr PolicyRoute, linkIndex int) error {
	_, ipnet, err := net.ParseCIDR(pr.CIDR)
	if err != nil {
		return err
	}
	fam := netlinkFamily(pr.Family)
	if err := b.ensurePolicyRule(ipnet, pr.Table, fam); err != nil {
		return err
	}
	r := &netlink.Route{
		LinkIndex: linkIndex,
		Dst:       ipnet,
		Scope:     netlink.SCOPE_LINK,
		Table:     pr.Table,
		Family:    fam,
	}
	// 只新增不覆盖：表内已有同目标时 RouteAdd 返回 EEXIST，视为已完成。
	if err := netlink.RouteAdd(r); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return nil
}

// ensurePolicyRule 确保存在「目标网段 → 专用表」的规则，已存在则跳过。
func (b *linuxBackend) ensurePolicyRule(dst *net.IPNet, table, fam int) error {
	if rules, err := netlink.RuleList(fam); err == nil {
		for i := range rules {
			if rules[i].Table == table && sameNet(rules[i].Dst, dst) {
				return nil
			}
		}
	}
	rule := netlink.NewRule()
	rule.Family = fam
	rule.Table = table
	rule.Priority = policyRulePriority
	rule.Dst = dst
	if err := netlink.RuleAdd(rule); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return nil
}

// removePolicyRoute 撤销一条策略路由：先摘规则，再删表内路由，最后同步状态记录。
func (b *linuxBackend) removePolicyRoute(pr PolicyRoute) (string, error) {
	_, ipnet, err := net.ParseCIDR(pr.CIDR)
	if err != nil {
		b.state.UnmarkPolicyRoute(pr.Dev, pr.CIDR)
		_ = b.state.Save()
		return "", nil
	}
	fam := netlinkFamily(pr.Family)
	if err := b.removePolicyRule(ipnet, pr.Table, fam); err != nil {
		return "", err
	}
	del := &netlink.Route{Dst: ipnet, Table: pr.Table, Family: fam}
	if err := netlink.RouteDel(del); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	b.state.UnmarkPolicyRoute(pr.Dev, pr.CIDR)
	_ = b.state.Save()
	return fmt.Sprintf("已撤销策略路由 %s（专用表 %d）", pr.CIDR, pr.Table), nil
}

// removePolicyRule 按内核中的实际条目删除规则（先列举再删除，避免构造不匹配）。
func (b *linuxBackend) removePolicyRule(dst *net.IPNet, table, fam int) error {
	rules, err := netlink.RuleList(fam)
	if err != nil {
		return err
	}
	for i := range rules {
		if rules[i].Table != table || !sameNet(rules[i].Dst, dst) {
			continue
		}
		r := rules[i]
		if err := netlink.RuleDel(&r); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// clearPolicyRoutesLocked 撤销某条连接（name 为空表示全部）下发的策略路由与 ip rule。
// 停用、删除连接、卸载以及接口已消失时都会调用，确保不留下影响系统的残留规则。
func (b *linuxBackend) clearPolicyRoutesLocked(name string) []string {
	var actions []string
	for _, pr := range b.state.PolicyRoutesCopy() {
		if name != "" && pr.Dev != name {
			continue
		}
		action, err := b.removePolicyRoute(pr)
		if err != nil {
			actions = append(actions, fmt.Sprintf("撤销策略路由 %s 失败：%v", pr.CIDR, err))
			continue
		}
		if action != "" {
			actions = append(actions, action)
		}
	}
	return actions
}

// sameNet 比较两个网段是否等价（忽略主机位）。
func sameNet(a, b *net.IPNet) bool {
	if a == nil || b == nil {
		return false
	}
	return maskedCIDR(a) == maskedCIDR(b)
}

// netlinkFamily 把 4/6 映射为 netlink 协议族常量。
func netlinkFamily(f int) int {
	if f == 6 {
		return netlink.FAMILY_V6
	}
	return netlink.FAMILY_V4
}

// hostRouteContext 收集主机上（排除本接口）的网段与既有路由。
func (b *linuxBackend) hostRouteContext(excludeIdx int) ([]string, []HostRoute, error) {
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

// eachRoute 遍历系统**全部路由表**中的路由。
//
// 两个必须显式处理的细节（netlink 库的默认行为对我们都不合适）：
//  1. 默认会跳过非 main 表。而策略路由、多出口分流会把默认路由放进自定义表，
//     只看 main 表就会得出「没有默认路由」的错误结论（内网访问转不出去即源于此）。
//     传 RT_FILTER_TABLE + 通配表号（Route.Table 为 0，即 RT_TABLE_UNSPEC）表示「任意表」。
//  2. 用 Iter 版本逐条交付：内核在 dump 途中被打断（NLM_F_DUMP_INTR，例如 Docker
//     正在增删路由）时，已经读到的部分仍然有效，不该整批丢弃。
//
// 传输途中被打断产生的 ErrDumpInterrupted 会被忽略：已交付的部分对调用方仍然可用。
func eachRoute(family int, f func(netlink.Route)) error {
	err := netlink.RouteListFilteredIter(
		family,
		&netlink.Route{Table: 0},
		netlink.RT_FILTER_TABLE,
		func(r netlink.Route) bool {
			f(r)
			return true
		})
	if errors.Is(err, netlink.ErrDumpInterrupted) {
		return nil
	}
	return err
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
func (b *linuxBackend) captureBaselineLocked() {
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
func (b *linuxBackend) Heal(ctx context.Context) ([]string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.captureBaselineLocked()
	return b.healLocked()
}

func (b *linuxBackend) healLocked() ([]string, error) {
	var actions []string

	managed := map[int]string{}
	for _, name := range b.state.ManagedCopy() {
		if l, err := netlink.LinkByName(name); err == nil {
			managed[l.Attrs().Index] = name
		} else {
			// 接口已不存在，清理记录，并撤销它可能留下的 ip rule 与口令指纹
			actions = append(actions, b.clearPolicyRoutesLocked(name)...)
			b.state.UnmarkManaged(name)
			b.state.DropPskFingerprints(name)
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
func (b *linuxBackend) hasForeignDefault(managed map[int]string) bool {
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
func (b *linuxBackend) restoreBaselineLocked() []string {
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

// foreignInterfacesLocked 列出内核里存在、但不属于本应用的 WireGuard 接口。
// 只读，不做任何修改。
func (b *linuxBackend) foreignInterfacesLocked(managed map[int]string) []model.ForeignInterface {
	out := []model.ForeignInterface{}
	// 兼容模式（用户态）的网卡与其它应用的 TUN 在 link 类型上无从区分，
	// 此时放弃「识别他人残留」这项能力：宁可漏报，也不误删用户别的网卡。
	if !b.driver.ForeignSupported() {
		return out
	}
	links, err := netlink.LinkList()
	if err != nil {
		return out
	}
	for _, l := range links {
		// 只看本模式能可靠识别的 WireGuard 网卡，绝不把普通网卡当作疑似残留上报
		if !b.driver.Identify(l) {
			continue
		}
		if _, ours := managed[l.Attrs().Index]; ours {
			continue
		}
		name := l.Attrs().Name
		if b.state.IsManaged(name) {
			continue
		}
		fi := model.ForeignInterface{
			Name: name,
			Up:   l.Attrs().Flags&net.FlagUp != 0,
		}
		if addrs, err := netlink.AddrList(l, netlink.FAMILY_ALL); err == nil {
			for _, a := range addrs {
				if a.IPNet != nil && !a.IPNet.IP.IsLinkLocalUnicast() {
					fi.Addresses = append(fi.Addresses, a.IPNet.String())
				}
			}
		}
		if dev, err := b.driver.Read(name); err == nil && dev != nil {
			fi.ListenPort = dev.ListenPort
			fi.PeerCount = len(dev.Peers)
		}
		out = append(out, fi)
	}
	return out
}

// DeleteForeignInterface 删除疑似残留的 WireGuard 接口。
//
// 这是全项目唯一一处会触碰「非本应用创建」对象的能力，因此设了三道闸：
//  1. 必须是 link 类型为 wireguard 的接口 —— 普通网卡、网桥、VLAN 一律拒绝；
//  2. 已在受管列表里的接口必须走正常删除流程，这里直接拒绝，避免绕过状态记录；
//  3. 调用方（界面）还要求用户输入接口名二次确认。
func (b *linuxBackend) DeleteForeignInterface(name string) ([]string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errors.New("请指定要删除的网卡名称")
	}
	if b.state.IsManaged(name) {
		return nil, fmt.Errorf("%s 是本应用创建的连接，请到「我的连接」里删除它", name)
	}
	if !b.driver.ForeignSupported() {
		return nil, errors.New("当前为兼容模式，系统里的 TUN 网卡无法与其它应用的网卡安全区分，" +
			"为避免误删已停用该功能")
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		var notFound netlink.LinkNotFoundError
		if errors.As(err, &notFound) {
			return []string{fmt.Sprintf("%s 已不存在，无需清理", name)}, nil
		}
		return nil, err
	}
	if kind := link.Type(); kind != "wireguard" {
		return nil, fmt.Errorf("%s 的类型是 %q，不是 WireGuard 网卡，本应用拒绝删除", name, kind)
	}

	var actions []string
	// 顺手撤销本应用记录过的、与该名称相关的策略路由
	actions = append(actions, b.clearPolicyRoutesLocked(name)...)
	if err := netlink.LinkDel(link); err != nil {
		return actions, fmt.Errorf("删除 %s 失败: %w", name, err)
	}
	b.state.DropPskFingerprints(name)
	_ = b.state.Save()
	actions = append(actions, fmt.Sprintf("已删除残留网卡 %s，其占用的端口已释放", name))
	return actions, nil
}

// DeleteInterface 删除接口。
func (b *linuxBackend) DeleteInterface(name string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.deleteLocked(name)
}

func (b *linuxBackend) deleteLocked(name string) error {
	if !b.state.IsManaged(name) {
		// 铁规则 1：不删除不是自己创建的接口。
		return fmt.Errorf("接口 %s 不是本应用创建的，为避免影响系统功能已拒绝删除", name)
	}
	// 先撤销该连接的策略路由与 ip rule，再删网卡：
	// 网卡一删，它在专用表里的路由会随之消失，但 ip rule 会留下，必须自己清掉。
	b.clearPolicyRoutesLocked(name)
	// 删除交给驱动：内核模式等价于删除网卡；兼容模式还要关闭进程内的用户态设备
	// 并回收它的 TUN —— 只删网卡会在进程里留下仍持有套接字的僵尸设备。
	if err := b.driver.Delete(name); err != nil {
		return fmt.Errorf("删除接口 %s 失败: %w", name, err)
	}
	b.state.UnmarkManaged(name)
	b.state.DropPskFingerprints(name)
	_ = b.state.Save()
	return nil
}

// Cleanup 删除本应用创建的全部接口与残留路由（用于「停用」与「卸载」）。
func (b *linuxBackend) Cleanup(ctx context.Context) ([]string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	var actions []string
	// 先撤掉内网访问规则（专用表 + 系统链里带标记的放行规则），再删接口
	if b.clearNATLocked() {
		actions = append(actions, "已移除内网访问转发规则")
		b.state.SetNAT("", nil, nil)
		_ = b.state.Save()
	}
	// 再摘掉全部策略路由与 ip rule，确保卸载后内核里不留任何本应用的痕迹
	actions = append(actions, b.clearPolicyRoutesLocked("")...)
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
	b.driver.Reset()
	return actions, nil
}

// Snapshot 采集实时状态。
func (b *linuxBackend) Snapshot(names []string) ([]model.InterfaceStatus, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	devs, err := b.driver.List()
	if err != nil {
		b.driver.Reset()
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
func (b *linuxBackend) Inspect(ctx context.Context) (model.NetworkReport, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	rep := model.NetworkReport{RouteInfoReadable: true, ManagedInterfaces: b.state.ManagedCopy()}
	managed := map[int]string{}
	for _, name := range rep.ManagedInterfaces {
		if l, err := netlink.LinkByName(name); err == nil {
			managed[l.Attrs().Index] = name
		}
	}
	// 疑似残留：内核里有、但本应用不认的 WireGuard 网卡（只读上报，绝不自动处理）
	rep.ForeignInterfaces = b.foreignInterfacesLocked(managed)
	// 内网访问规则状态与系统转发策略（用于诊断「连上了但访问不了其它设备」）
	rep.NAT = b.natStatusLocked()
	rep.ForwardPolicyDrop = b.systemForwardPolicyDropLocked()

	// 默认路由同样要读全部路由表：只看 main 表会漏掉策略路由 / 多出口分流下的默认路由，
	// 让用户看到「系统没有默认路由」，而实际上有一条，只是不在 main 表里。
	_ = eachRoute(netlink.FAMILY_ALL, func(r netlink.Route) {
		if !isDefaultRoute(r) {
			return
		}
		entry := model.DefaultRoute{Family: r.Family, Metric: r.Priority, Table: r.Table}
		if r.Gw != nil {
			entry.Gw = r.Gw.String()
		}
		entry.Dev = routeDevName(r)
		if name, ours := managed[r.LinkIndex]; ours {
			entry.OwnedByUs = true
			entry.Dev = name
			rep.StrayDefaults = append(rep.StrayDefaults, entry)
			return
		}
		rep.Defaults = append(rep.Defaults, entry)
	})
	return rep, nil
}
