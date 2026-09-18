// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 newcdl <newcdl@163.com>

//go:build linux

package wgback

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// kernelDriver 是标准模式：读写内核 wireguard 模块，全部经 generic netlink 完成。
type kernelDriver struct {
	client *wgctrl.Client
	caps   Capabilities
}

func newKernelDriver() *kernelDriver {
	return &kernelDriver{caps: detectCaps("kernel")}
}

func (d *kernelDriver) Kind() string { return "kernel" }

func (d *kernelDriver) Caps() Capabilities { return d.caps }

// ForeignSupported：内核模式能按 link 类型可靠区分「别人的 wireguard 网卡」。
func (d *kernelDriver) ForeignSupported() bool { return true }

func (d *kernelDriver) Identify(l netlink.Link) bool {
	return l != nil && l.Type() == "wireguard"
}

func (d *kernelDriver) Ready() error {
	_, err := d.conn()
	return err
}

func (d *kernelDriver) Reset() {
	if d.client != nil {
		_ = d.client.Close()
		d.client = nil
	}
}

func (d *kernelDriver) conn() (*wgctrl.Client, error) {
	if d.client != nil {
		return d.client, nil
	}
	c, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("连接内核 WireGuard 接口失败（请确认已完成上电准备）: %w", err)
	}
	d.client = c
	return c, nil
}

func (d *kernelDriver) Ensure(name string, mtu int) (bool, error) {
	attrs := netlink.LinkAttrs{Name: name}
	if mtu > 0 {
		attrs.MTU = mtu
	}
	if err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: attrs}); err != nil {
		if isUnsupportedErrno(err) {
			return false, fmt.Errorf("%w: 创建内核接口 %s 失败（%v）", errBackendUnsupported, name, err)
		}
		return false, fmt.Errorf("创建接口失败: %w", err)
	}
	return true, nil
}

func (d *kernelDriver) Read(name string) (*wgtypes.Device, error) {
	c, err := d.conn()
	if err != nil {
		return nil, err
	}
	dev, err := c.Device(name)
	if err != nil {
		// 设备不存在、或内核尚未为它建立任何配置 —— 一律按「读不到」处理，
		// 调用方会退化为「该接口的全部字段都按新增下发」，这正是我们想要的。
		return nil, nil
	}
	return dev, nil
}

func (d *kernelDriver) Configure(name string, cfg wgtypes.Config) error {
	c, err := d.conn()
	if err != nil {
		return err
	}
	if err := c.ConfigureDevice(name, cfg); err != nil {
		return fmt.Errorf("下发配置失败: %w", err)
	}
	return nil
}

func (d *kernelDriver) Delete(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil
	}
	return netlink.LinkDel(link)
}

func (d *kernelDriver) List() ([]*wgtypes.Device, error) {
	c, err := d.conn()
	if err != nil {
		return nil, err
	}
	devs, err := c.Devices()
	if err != nil {
		// 句柄可能已失效（内核重启、模块重载），断开以便下一轮重连。
		d.Reset()
		return nil, err
	}
	return devs, nil
}

// kernelModuleAvailable 判断内核是否具备 WireGuard 能力。
//
// 只看只读信息，不做任何探测性写操作：
//   - /sys/module/wireguard 存在：已经加载（含编进内核的情况）；
//   - 模块文件存在：尚未加载但可以按需加载 —— 创建网卡时内核会自行
//     request_module("rtnl-link-wireguard")，所以这也算「可用」。
func kernelModuleAvailable() bool {
	if _, err := os.Stat("/sys/module/wireguard"); err == nil {
		return true
	}
	for _, dir := range []string{"/lib/modules", "/usr/lib/modules"} {
		matches, _ := filepath.Glob(filepath.Join(dir, "*", "kernel/net/wireguard/wireguard.ko*"))
		if len(matches) > 0 {
			return true
		}
	}
	return false
}

// isUnsupportedErrno 判断错误是否表示「本内核根本不支持这类网卡」。
//
// 刻意不含 EINVAL：那更可能是参数问题，误判成「不支持」会导致
// 静默回退到用户态、把真正的配置错误掩盖掉。
func isUnsupportedErrno(err error) bool {
	return errors.Is(err, syscall.EOPNOTSUPP) ||
		errors.Is(err, syscall.EPROTONOSUPPORT) ||
		errors.Is(err, syscall.ENODEV) ||
		errors.Is(err, syscall.ENXIO)
}
