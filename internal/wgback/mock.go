//go:build !linux

package wgback

import (
	"context"
	"fmt"
	"hash/fnv"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"fnwg/internal/model"
	"fnwg/internal/wgkey"
)

// mockBackend 是开发/演示用的内存后端。
// 非 Linux 平台（例如开发机）无法创建内核 WireGuard 设备，这里用内存态模拟，
// 保证前端与 API 可以完整联调。生产环境运行在 fnOS（Linux）上会使用 kernelBackend。
//
// 它同样遵守安全契约：只操作自己创建过的接口，不做任何路由操作。
type mockBackend struct {
	mu    sync.Mutex
	devs  map[string]*mockDevice
	state *State
}

type mockDevice struct {
	spec  model.InterfaceSpec
	peers map[string]*mockPeer
}

type mockPeer struct {
	spec model.PeerSpec
	rx   int64
	tx   int64
}

// New 创建内存后端。
func New(statePath string) Backend {
	return &mockBackend{devs: map[string]*mockDevice{}, state: LoadState(statePath)}
}

func (b *mockBackend) Kind() string { return "mock" }

func (b *mockBackend) Caps() Capabilities {
	return Capabilities{Backend: "mock", KernelModule: false, TunDevice: false}
}

func (b *mockBackend) ManagedInterfaces() []string { return b.state.ManagedCopy() }

func (b *mockBackend) Heal(ctx context.Context) ([]string, error) {
	// 内存后端不存在系统路由，无需修复。
	return nil, nil
}

func (b *mockBackend) Cleanup(ctx context.Context) ([]string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var actions []string
	for _, name := range b.state.ManagedCopy() {
		actions = append(actions, fmt.Sprintf("删除本应用创建的接口 %s（模拟）", name))
		delete(b.devs, name)
		b.state.UnmarkManaged(name)
	}
	_ = b.state.Save()
	return actions, nil
}

func (b *mockBackend) Inspect(ctx context.Context) (model.NetworkReport, error) {
	return model.NetworkReport{
		ManagedInterfaces: b.state.ManagedCopy(),
		ForeignInterfaces: []model.ForeignInterface{},
		NAT:               b.NATStatus(),
	}, nil
}

// DeleteForeignInterface 演示模式下没有真实的残留网卡可删。
func (b *mockBackend) DeleteForeignInterface(name string) ([]string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return []string{fmt.Sprintf("演示模式：%s 是模拟对象，未做任何删除", name)}, nil
}

// NATStatus 演示模式下不产生真实的转发规则。
func (b *mockBackend) NATStatus() model.NATStatus {
	b.mu.Lock()
	defer b.mu.Unlock()
	sources := []string{}
	for name, dev := range b.devs {
		if !b.state.IsManaged(name) || !dev.spec.AllowLAN {
			continue
		}
		for _, a := range dev.spec.Addresses {
			if _, n, err := net.ParseCIDR(strings.TrimSpace(a)); err == nil && n.IP.To4() != nil {
				sources = append(sources, (&net.IPNet{IP: n.IP.Mask(n.Mask), Mask: n.Mask}).String())
			}
		}
	}
	if len(sources) == 0 {
		return model.NATStatus{
			Sources:   []string{},
			WANs:      []string{},
			IPForward: true,
			Checks: []model.NATCheck{
				{Key: "rules", Label: "转发规则", OK: false,
					Detail: "演示模式：没有已打开「内网访问」开关的连接"},
				{Key: "ip_forward", Label: "内核转发", OK: true, Detail: "演示模式：未读取真实内核参数"},
			},
		}
	}
	sort.Strings(sources)
	return model.NATStatus{
		Active:    true,
		Sources:   sources,
		WANs:      []string{},
		IPForward: true,
		Note:      "演示模式：未产生真实的转发规则",
		Checks: []model.NATCheck{
			{Key: "rules", Label: "转发规则", OK: true,
				Detail: fmt.Sprintf("演示模式：将为 %s 做源地址改写", strings.Join(sources, "、"))},
			{Key: "ip_forward", Label: "内核转发", OK: true, Detail: "演示模式：未读取真实内核参数"},
		},
	}
}

func (b *mockBackend) Apply(specs []model.InterfaceSpec, opts ApplyOptions) (Diff, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	var diff Diff
	seen := map[string]bool{}
	for _, spec := range specs {
		seen[spec.Name] = true
		dev, ok := b.devs[spec.Name]
		if !ok {
			if !b.state.IsManaged(spec.Name) {
				// 与真实后端一致的接管保护
				exists := false
				for n := range b.devs {
					if n == spec.Name {
						exists = true
					}
				}
				if exists {
					return diff, fmt.Errorf("系统上已存在名为 %s 的网卡，但它不是本应用创建的，已拒绝接管", spec.Name)
				}
			}
			diff.Append("创建 WireGuard 接口 %s（模拟）", spec.Name)
			if opts.DryRun {
				continue
			}
			dev = &mockDevice{peers: map[string]*mockPeer{}}
			b.devs[spec.Name] = dev
			b.state.MarkManaged(spec.Name)
			_ = b.state.Save()
		}
		dev.spec = spec
		keep := map[string]bool{}
		for _, p := range spec.Peers {
			keep[p.PublicKey] = true
			if old, ok := dev.peers[p.PublicKey]; ok {
				old.spec = p
			} else {
				dev.peers[p.PublicKey] = &mockPeer{spec: p}
			}
		}
		for pk := range dev.peers {
			if !keep[pk] {
				delete(dev.peers, pk)
			}
		}
		diff.Append("同步 %s 的 %d 个节点（模拟）", spec.Name, len(dev.peers))
	}
	if opts.RemoveMissing {
		for _, name := range b.state.ManagedCopy() {
			if seen[name] {
				continue
			}
			diff.Append("删除多余接口 %s（模拟）", name)
			if !opts.DryRun {
				delete(b.devs, name)
				b.state.UnmarkManaged(name)
			}
		}
		_ = b.state.Save()
	}
	return diff, nil
}

func (b *mockBackend) DeleteInterface(name string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.state.IsManaged(name) {
		return fmt.Errorf("接口 %s 不是本应用创建的，已拒绝删除", name)
	}
	delete(b.devs, name)
	b.state.UnmarkManaged(name)
	_ = b.state.Save()
	return nil
}

func (b *mockBackend) Snapshot(names []string) ([]model.InterfaceStatus, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	filter := map[string]bool{}
	for _, n := range names {
		filter[n] = true
	}
	now := time.Now()
	out := make([]model.InterfaceStatus, 0, len(b.devs))
	for name, dev := range b.devs {
		if !b.state.IsManaged(name) {
			continue
		}
		if len(filter) > 0 && !filter[name] {
			continue
		}
		st := model.InterfaceStatus{
			Name:       name,
			Up:         dev.spec.Up,
			ListenPort: dev.spec.ListenPort,
			FWMark:     dev.spec.FWMark,
			MTU:        dev.spec.MTU,
			Addresses:  append([]string{}, dev.spec.Addresses...),
		}
		if dev.spec.PrivateKey != "" {
			if pub, err := wgkey.PublicKey(dev.spec.PrivateKey); err == nil {
				st.PublicKey = pub
			}
		}
		for pk, p := range dev.peers {
			rxBps := simulatedRate(pk, "rx")
			txBps := simulatedRate(pk, "tx")
			p.rx += rxBps
			p.tx += txBps
			ps := model.PeerStatus{
				PublicKey:     pk,
				Endpoint:      p.spec.Endpoint,
				AllowedIPs:    append([]string{}, p.spec.AllowedIPs...),
				Keepalive:     p.spec.Keepalive,
				LastHandshake: now.Add(-45 * time.Second),
				RxBytes:       p.rx,
				TxBytes:       p.tx,
				RxRate:        float64(rxBps),
				TxRate:        float64(txBps),
				PresharedKey:  p.spec.PresharedKey != "",
			}
			st.Peers = append(st.Peers, ps)
		}
		out = append(out, st)
	}
	return out, nil
}

// simulatedRate 依据公钥散列生成稳定的模拟速率（字节/采样周期）。
func simulatedRate(pub, dir string) int64 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(pub + dir))
	return int64(h.Sum32()%4096) + 64
}
