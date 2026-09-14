package wgback

import (
	"fmt"
	"net"
	"strings"
)

// 本文件是「绝不破坏 NAS 系统网络」的核心防线。
//
// 全部决策都在 PlanRoutes 这个纯函数里完成，不依赖系统状态，可被单元测试穷举覆盖。
// 只有同时满足下面所有条件的网段，才允许被下发：
//   1. 显式开启了路由管理（默认关闭）；
//   2. 不是默认路由 0.0.0.0/0 或 ::/0 —— 主机默认路由永远归系统所有；
//   3. 与本接口自身网段不重叠；
//   4. 与主机上其他网卡的网段不重叠（否则会抢走局域网/系统服务可达性）；
//   5. 主机上不存在同目标的路由（存在即跳过，绝不覆盖，等价于 wg-quick 的 route add 语义）。
//
// 任何一条不满足都只记录原因并跳过，绝不返回错误中断，更不会去改动系统已有路由。
//
// 另外，即便全部条件满足要被下发，也**不会写进系统主路由表**：
// 下发目标一律是本应用专用的策略路由表，并用 ip rule 只对目标网段生效，
// 详见 policyroute.go。这样 `ip route show` 与安装前完全一致。

// HostRoute 是主机上已存在的一条路由。
type HostRoute struct {
	// Dst 为 CIDR；空字符串表示默认路由。
	Dst       string
	LinkIndex int
	HasGw     bool
	Family    int
}

// RoutePlanInput 是路由决策的全部输入。
type RoutePlanInput struct {
	ManageRoutes   bool
	InterfaceName  string
	InterfaceIndex int
	InterfaceAddrs []string
	PeerAllowedIPs []string
	HostNetworks   []string
	ExistingRoutes []HostRoute
}

// RouteSkip 是一条被拒绝下发的路由及原因。
type RouteSkip struct {
	CIDR   string
	Reason string
}

// RoutePlan 是路由决策结果。
type RoutePlan struct {
	Add  []string
	Skip []RouteSkip
}

// IsDefaultRouteCIDR 判断是否为默认路由（前缀长度为 0）。
func IsDefaultRouteCIDR(cidr string) bool {
	cidr = strings.TrimSpace(cidr)
	if cidr == "0.0.0.0/0" || cidr == "::/0" || cidr == "0/0" || cidr == "0::/0" {
		return true
	}
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	ones, _ := n.Mask.Size()
	return ones == 0
}

// PlanRoutes 计算允许下发的路由清单。
func PlanRoutes(in RoutePlanInput) RoutePlan {
	plan := RoutePlan{}
	ifaceNets := parseCIDRs(in.InterfaceAddrs)

	if !in.ManageRoutes {
		// 默认路径：完全不动系统路由。
		//
		// 这里只汇报「用户确实需要知道」的网段：落点在本连接自身网段内的地址，
		// 已经被内核为该网卡自动建立的直连路由覆盖（例如 wg200 配了 10.210.0.1/24，
		// 设备地址 10.210.0.2 就在这条直连路由里），本来就不需要任何动作，
		// 因此不产生提示，避免把正常运行状态写成「警告」吓到用户。
		for _, raw := range in.PeerAllowedIPs {
			cidr := strings.TrimSpace(raw)
			if cidr == "" {
				continue
			}
			if _, n, err := net.ParseCIDR(cidr); err == nil && coveredBy(ifaceNets, n) {
				continue
			}
			plan.Skip = append(plan.Skip, RouteSkip{CIDR: cidr, Reason: "路由管理未开启，本应用不修改系统路由"})
		}
		return plan
	}

	hostNets := parseCIDRs(in.HostNetworks)

	// 主机上已存在的目标（含默认路由），绝不覆盖
	existing := map[string]bool{}
	for _, r := range in.ExistingRoutes {
		if r.Dst == "" {
			existing["0.0.0.0/0"] = true
			existing["::/0"] = true
			continue
		}
		existing[r.Dst] = true
	}

	seen := map[string]bool{}
	for _, raw := range in.PeerAllowedIPs {
		cidr := strings.TrimSpace(raw)
		if cidr == "" || seen[cidr] {
			continue
		}
		seen[cidr] = true

		ip, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			plan.Skip = append(plan.Skip, RouteSkip{CIDR: cidr, Reason: "网段格式不合法"})
			continue
		}
		ipnet.IP = ip

		// 红线 1：默认路由永远归系统所有
		if ones, _ := ipnet.Mask.Size(); ones == 0 {
			plan.Skip = append(plan.Skip, RouteSkip{CIDR: cidr, Reason: "禁止接管系统默认路由（会切断 NAS 自身上网与 FN Connect）"})
			continue
		}
		// 红线 2：本接口自身网段由内核自动建立直连路由
		if overlapsAny(ipnet, ifaceNets) {
			plan.Skip = append(plan.Skip, RouteSkip{CIDR: cidr, Reason: "属于本连接自身网段，无需添加"})
			continue
		}
		// 红线 3：与主机其他网段重叠会抢走局域网/系统服务可达性
		if overlapsAny(ipnet, hostNets) {
			plan.Skip = append(plan.Skip, RouteSkip{CIDR: cidr, Reason: "与 NAS 现有网段重叠，为避免影响系统网络已跳过"})
			continue
		}
		// 红线 4：主机已有同目标路由，绝不覆盖
		if existing[ipnet.String()] || existing[cidr] {
			plan.Skip = append(plan.Skip, RouteSkip{CIDR: cidr, Reason: "NAS 上已存在相同目标的路线，不覆盖"})
			continue
		}
		plan.Add = append(plan.Add, ipnet.String())
	}
	return plan
}

func parseCIDRs(list []string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(list))
	for _, s := range list {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		ip, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			continue
		}
		ipnet.IP = ip
		out = append(out, ipnet)
	}
	return out
}

// overlapsAny 判断目标网段是否与给定网段存在包含关系（双向）。
func overlapsAny(target *net.IPNet, list []*net.IPNet) bool {
	for _, n := range list {
		if (n.IP.To4() == nil) != (target.IP.To4() == nil) {
			continue
		}
		if n.Contains(target.IP) || target.Contains(n.IP) {
			return true
		}
	}
	return false
}

// coveredBy 判断目标网段是否已被 list 中某个网段的直连路由**完整**覆盖。
//
// 与 overlapsAny 的区别：overlapsAny 只要沾边就算命中（用于「保守拒绝下发」），
// 而这里要求 list 中的网段前缀不长于目标网段且包含其起始地址，
// 也就是「目标里的每一个地址都在这条直连路由里」。例如：
//
//	接口 10.210.0.1/24 + 目标 10.210.0.2/32 → 被覆盖（直连路由已够用）
//	接口 10.210.0.1/24 + 目标 10.210.0.0/16 → 未被覆盖（还有 10.211.x.x 等也在这个目标里）
func coveredBy(list []*net.IPNet, target *net.IPNet) bool {
	if target == nil {
		return false
	}
	to, _ := target.Mask.Size()
	for _, n := range list {
		if (n.IP.To4() == nil) != (target.IP.To4() == nil) {
			continue
		}
		no, _ := n.Mask.Size()
		if no <= to && n.Contains(target.IP) {
			return true
		}
	}
	return false
}

// ValidatePeerAllowedIPs 校验服务端准入地址。
// 服务端不允许出现默认路由写法：那是客户端的上网方式，填在这里会改变 NAS 自身网络。
func ValidatePeerAllowedIPs(list []string) error {
	for _, cidr := range list {
		if IsDefaultRouteCIDR(cidr) {
			return fmt.Errorf("「分配给这台设备的内部地址」不能填写 %s。"+
				"这是设备的“上网方式”，请改用下面的「设备上网方式」设置；"+
				"填在这里会修改 NAS 自身的网络，可能影响 FN Connect 等系统功能", strings.TrimSpace(cidr))
		}
	}
	return nil
}

// DescribeSkip 汇总跳过原因，用于日志与界面展示。
func DescribeSkip(skips []RouteSkip) string {
	if len(skips) == 0 {
		return ""
	}
	parts := make([]string, 0, len(skips))
	for _, s := range skips {
		parts = append(parts, fmt.Sprintf("%s（%s）", s.CIDR, s.Reason))
	}
	return strings.Join(parts, "；")
}
