//go:build linux

package wgback

import (
	"errors"
	"os"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// 本文件定义「WireGuard 设备驱动」抽象层。
//
// 为什么需要它：本应用有两套数据面实现 ——
//   - kernel：内核 wireguard 模块，经 wgctrl（generic netlink）读写；
//   - userspace：用户态 wireguard-go，经其 UAPI 读写。
//
// 两者在「设备如何创建、节点如何读写」上完全不同，但在「MTU、地址、起停、
// 策略路由、内网访问、残留自愈」上完全是同一套 netlink 操作。把差异收敛到本接口后，
// 这些安全规则（铁规则 1~4）与「只下发真正变化的字段」的防抖动逻辑只保留一份实现，
// 改一处即对两种模式同时生效 —— 反过来若各写一套后端，等于把安全关键代码抄两遍，
// 迟早会分叉出只修了一半的洞。
//
// 接口刻意沿用 wgtypes 作为配置载体：两种实现本就在同一个二进制里，
// 让它自己把 UAPI 文本解析成 wgtypes.Device，上层就无需为「两种结构体」再写一套比较逻辑。

// wireGuardDriver 抽象「WireGuard 设备」这一层。
type wireGuardDriver interface {
	// Kind 返回后端标识：kernel | userspace。
	Kind() string
	// Caps 报告宿主环境能力（构造时算一次，Health 会反复读）。
	Caps() Capabilities
	// Ready 检查驱动是否可用于后续操作。
	//
	// 语义刻意宽松：内核模块「尚未加载」不算不可用 —— 创建网卡时内核会按需
	// 加载 rtnl-link-wireguard，此时提前报错会误伤「模块可加载但当前未加载」的正常系统。
	Ready() error
	// Reset 丢弃内部句柄以便下次重连（内核）；用户态实现无需处理。
	Reset()
	// Ensure 确保名为 name 的设备存在（不存在则创建，并按 mtu 设定），
	// created 表示本次是否真的新建了设备。
	Ensure(name string, mtu int) (created bool, err error)
	// Read 读取设备当前配置；设备不存在（或尚未配置）时返回 (nil, nil) 而非错误 ——
	// 「刚创建还没来得及配置」是正常状态，调用方据此退化为「全部按新增处理」。
	Read(name string) (*wgtypes.Device, error)
	// Configure 下发设备与节点配置。
	Configure(name string, cfg wgtypes.Config) error
	// Delete 删除设备，并回收该实现占用的额外资源。
	Delete(name string) error
	// List 返回该模式下的全部设备，用于状态快照与残留检测。
	//
	// 用户态实现只返回本进程创建的那些：它无从枚举「别人的」用户态设备，
	// 也不该假装自己知道。
	List() ([]*wgtypes.Device, error)
	// Identify 判断一个网卡是否为本模式下的 WireGuard 设备。
	Identify(l netlink.Link) bool
	// ForeignSupported 表示本模式能否安全识别「他人创建的同类设备」。
	//
	// 内核模式按 link 类型（wireguard）区分，可靠；
	// 用户态模式的设备同样是 TUN，无法与其它应用的 TUN 区分，因此报告 false ——
	// 此时残留检测上报空列表、删除一律拒绝：宁可漏报残留，也不误删用户的其它网卡。
	ForeignSupported() bool
}

// errBackendUnsupported 表示「当前后端在这个宿主上根本用不了」。
// 上层据此决定是否回退到另一种实现，而不是把一句内核错误直接甩给用户。
var errBackendUnsupported = errors.New("当前数据面后端在此系统上不可用")

// envBackendMode 允许运维强制指定数据面后端，留空表示自动选择。
const envBackendMode = "FNWG_BACKEND"

// 后端模式取值。
const (
	modeAuto      = "auto"
	modeKernel    = "kernel"
	modeUserspace = "userspace"
)

// detectCaps 采集宿主环境能力。
//
// 结果在驱动构造时算一次：模块是否可用在进程生命周期内不会变化，
// 而 Health 每次刷新都会读 Caps，不能每次都去 glob 模块目录。
func detectCaps(kind string) Capabilities {
	return Capabilities{
		Backend:      kind,
		KernelModule: kernelModuleAvailable(),
		TunDevice:    tunDeviceAvailable(),
	}
}

// tunDeviceAvailable 判断用户态回退的前提是否具备。
func tunDeviceAvailable() bool {
	_, err := os.Stat("/dev/net/tun")
	return err == nil
}

// backendLabel 把后端标识翻译成界面用语，用于变更说明。
func backendLabel(kind string) string {
	switch kind {
	case modeKernel:
		return "标准模式"
	case modeUserspace:
		return "兼容模式"
	default:
		return kind
	}
}
