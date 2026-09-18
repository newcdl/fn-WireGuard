// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

//go:build linux

package wgback

import (
	"fmt"
	"sync"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// userspaceDriver 是兼容模式：设备由本进程内的 wireguard-go 提供。
//
// 什么时候用它：宿主内核没有（且无法按需加载）wireguard 模块，但提供 /dev/net/tun。
// 代价是收发要经过用户态转发，吞吐与 CPU 占用不如内核实现；
// 好处是在任何能建 TUN 的 Linux 上都能把隧道拉起来。
//
// 与内核模式共享的安全边界完全一致（见 linuxBackend）：
// 只操作本应用创建并在 state 里登记过的设备、绝不碰系统默认路由。
// 唯一的差别是「识别他人 wireguard 网卡」的能力 —— 见 ForeignSupported。
type userspaceDriver struct {
	mu   sync.Mutex
	devs map[string]*userspaceDevice
	caps Capabilities
}

// userspaceDevice 是本进程持有的一台用户态 WireGuard 设备。
type userspaceDevice struct {
	tun tun.Device
	dev *device.Device
}

func newUserspaceDriver() *userspaceDriver {
	return &userspaceDriver{
		devs: map[string]*userspaceDevice{},
		caps: detectCaps("userspace"),
	}
}

func (d *userspaceDriver) Kind() string { return "userspace" }

func (d *userspaceDriver) Caps() Capabilities { return d.caps }

// ForeignSupported：用户态网卡与其它应用的 TUN 在 link 类型上完全一样，
// 无法可靠区分「我们上次留下的残留」与「别人正在用的 TUN」。
// 于是明确放弃这项能力，而不是拿名字去猜 —— 猜错的代价是删掉用户别的应用。
func (d *userspaceDriver) ForeignSupported() bool { return false }

// Identify：兼容模式下一切「猜测式识别」都返回否，残留检测因此上报空列表。
func (d *userspaceDriver) Identify(netlink.Link) bool { return false }

func (d *userspaceDriver) Ready() error {
	if !tunDeviceAvailable() {
		return fmt.Errorf("兼容模式需要 /dev/net/tun，但系统未提供该设备（容器环境请以 --device /dev/net/tun 启动）")
	}
	return nil
}

// Reset：用户态设备的句柄由本进程直接持有，不存在需要重连的 netlink 连接。
func (d *userspaceDriver) Reset() {}

func (d *userspaceDriver) Ensure(name string, mtu int) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.devs[name]; ok {
		return false, nil
	}
	if mtu <= 0 {
		mtu = device.DefaultMTU
	}
	tunDev, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return false, fmt.Errorf("创建用户态接口失败: %w", err)
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "fnwg "))
	// 先 Up 再下发配置：只有设备处于 up 状态，后续的 listen_port 才会真正绑定端口。
	if err := dev.Up(); err != nil {
		// Close 会一并关闭其 TUN，网卡随之从系统上消失，不留半成品。
		dev.Close()
		return false, fmt.Errorf("启动用户态接口失败: %w", err)
	}
	d.devs[name] = &userspaceDevice{tun: tunDev, dev: dev}
	return true, nil
}

func (d *userspaceDriver) Read(name string) (*wgtypes.Device, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	ud, ok := d.devs[name]
	if !ok {
		return nil, nil
	}
	raw, err := ud.dev.IpcGet()
	if err != nil {
		return nil, fmt.Errorf("读取用户态接口配置失败: %w", err)
	}
	return decodeUAPIGet(name, raw)
}

func (d *userspaceDriver) Configure(name string, cfg wgtypes.Config) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	ud, ok := d.devs[name]
	if !ok {
		return fmt.Errorf("用户态接口 %s 不存在", name)
	}
	if err := ud.dev.IpcSet(encodeUAPISet(cfg)); err != nil {
		return fmt.Errorf("下发配置失败: %w", err)
	}
	return nil
}

func (d *userspaceDriver) Delete(name string) error {
	d.mu.Lock()
	ud, ok := d.devs[name]
	if ok {
		delete(d.devs, name)
	}
	d.mu.Unlock()

	if ok {
		// Close 会一并关闭其 TUN，网卡随即从系统上消失。
		ud.dev.Close()
		return nil
	}
	// 不在本进程登记表中：多半是上次进程退出前留下的 TUN（内核里网卡还在）。
	if l, err := netlink.LinkByName(name); err == nil {
		return netlink.LinkDel(l)
	}
	return nil
}

func (d *userspaceDriver) List() ([]*wgtypes.Device, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]*wgtypes.Device, 0, len(d.devs))
	for name, ud := range d.devs {
		raw, err := ud.dev.IpcGet()
		if err != nil {
			// 单台设备读不到不该让整份快照失败：跳过它，其余照常显示。
			continue
		}
		dev, err := decodeUAPIGet(name, raw)
		if err != nil {
			continue
		}
		out = append(out, dev)
	}
	return out, nil
}
