// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

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

// mockBackend 是内存态数据面，供两处使用：
//
//  1. 非 Linux 平台（例如开发机）作为默认后端：那里无法创建内核 WireGuard 设备，
//     用内存态模拟即可让前端与 API 完整联调（见 backend_nonlinux.go）；
//  2. 各平台的单元测试：业务层测试不该依赖 root 与内核能力。
//     CI 的 runner 以非 root 运行，真实的 netlink 调用必然返回 operation not permitted。
//
// 因为第 2 条，本文件不限定平台：NewMock 在所有平台都可用，
// 只有「默认后端是谁」按平台区分（Linux 用 linuxBackend，见 linux.go）。
//
// 它同样遵守安全契约：只操作自己创建过的接口，不做任何路由操作。
type mockBackend struct {
	mu    sync.Mutex
	devs  map[string]*mockDevice
	state *State
	// applyErr 非空时 Apply 直接失败，用于测试「配置下发失败」的通知链路。
	applyErr error
	// healActions 非空时 Heal 返回它，用于测试「残留网络自愈」的通知链路。
	healActions []string
}

type mockDevice struct {
	spec  model.InterfaceSpec
	peers map[string]*mockPeer
	// linkDown 让网卡在快照里显示为「未工作」，用于测试连接掉线这一类场景。
	linkDown bool
}

type mockPeer struct {
	spec model.PeerSpec
	rx   int64
	tx   int64
}

// NewMock 创建内存后端。所有平台都可用，供开发与非特权测试使用；
// 生产环境请用 New（Linux 上是真实内核后端）。
func NewMock(statePath string) Backend {
	return &mockBackend{devs: map[string]*mockDevice{}, state: LoadState(statePath)}
}

func (b *mockBackend) Kind() string { return "mock" }

func (b *mockBackend) Caps() Capabilities {
	return Capabilities{Backend: "mock", KernelModule: false, TunDevice: false}
}

func (b *mockBackend) ManagedInterfaces() []string { return b.state.ManagedCopy() }

func (b *mockBackend) Heal(ctx context.Context) ([]string, error) {
	// 内存后端不存在系统路由，默认无需修复；测试可用 SetHealActions 指定结果。
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string{}, b.healActions...), nil
}

// SetHealActions 指定 Heal 的返回值，用于测试「残留网络自愈」的通知链路。
//
// 只有内存后端提供：真实环境里这类残留来自上一次异常退出或升级，
// 单元测试没法真的造一条系统路由出来。
func (b *mockBackend) SetHealActions(actions []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.healActions = append([]string{}, actions...)
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
// LANDevices 演示模式下给一台样板内网。
//
// 内存后端读不到真实邻居表，但拓扑图在演示环境里也应该有东西可看；
// Demo 标记会一路传到界面，明说这是样板数据而不是家里的机器。
func (b *mockBackend) LANDevices(ctx context.Context) (*model.LANReport, error) {
	return &model.LANReport{
		Demo:     true,
		Readable: true,
		Devices: []model.LANDevice{
			{IP: "192.168.1.1", MAC: "aa:bb:cc:00:00:01", Name: "主路由", Interface: "eth0", State: "reachable"},
			{IP: "192.168.1.20", MAC: "aa:bb:cc:00:00:20", Name: "书房的电脑", Interface: "eth0", State: "reachable"},
			{IP: "192.168.1.31", MAC: "aa:bb:cc:00:00:31", Interface: "eth0", State: "stale"},
			{IP: "192.168.1.40", MAC: "aa:bb:cc:00:00:40", Name: "打印机", Interface: "eth0", State: "stale"},
		},
	}, nil
}

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

// SetApplyError 让后续 Apply 直接返回该错误（传 nil 恢复正常）。
//
// 只有内存后端提供：真实环境里这类失败来自内核调用（权限、模块、
// 设备名冲突……），而单元测试需要一个可控的失败开关。
func (b *mockBackend) SetApplyError(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.applyErr = err
}

// SetLinkDown 让指定网卡在状态快照里显示为「未工作」，模拟内核侧掉线
// （网卡被其它工具停用或删除）。返回是否找到该网卡。
//
// 只有内存后端提供：真实内核里掉不掉线由内核决定，
// 而单元测试需要一个可控的「本应工作但没工作」场景。
func (b *mockBackend) SetLinkDown(name string, down bool) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	dev, ok := b.devs[name]
	if !ok {
		return false
	}
	dev.linkDown = down
	return true
}

func (b *mockBackend) Apply(specs []model.InterfaceSpec, opts ApplyOptions) (Diff, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	var diff Diff
	if b.applyErr != nil {
		return diff, b.applyErr
	}
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
			Up:         dev.spec.Up && !dev.linkDown,
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
