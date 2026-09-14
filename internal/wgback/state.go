package wgback

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// 铁规则：本应用只允许操作「自己创建过的」内核对象。
// 状态文件记录我们创建过的接口名，以及接管前的系统默认路由基线，
// 用于安全地限定清理范围，并在必要时恢复系统原本的上网路线。

// BaselineRoute 是接管前的系统默认路由快照。
type BaselineRoute struct {
	Family int    `json:"family"`
	Gw     string `json:"gw,omitempty"`
	Dev    string `json:"dev,omitempty"`
	Metric int    `json:"metric"`
	Table  int    `json:"table"`
}

// State 是需要跨进程、跨重启保留的安全状态。
type State struct {
	// ManagedInterfaces 由本应用创建的接口名。
	ManagedInterfaces []string `json:"managed_interfaces"`
	// ManagedPolicyRoutes 本应用写入专用策略路由表的路由及配套 ip rule。
	// 记录它是为了只清理自己创建的条目，绝不碰别人的规则。
	ManagedPolicyRoutes []PolicyRoute `json:"managed_policy_routes"`
	// BaselineDefaults 首次运行时的系统默认路由（仅快照，不修改系统配置）。
	BaselineDefaults []BaselineRoute `json:"baseline_default_routes"`
	// BaselineTaken 是否已采集过基线。
	BaselineTaken bool `json:"baseline_taken"`
	// PskFingerprints 记录上一次成功下发的二次加密口令指纹，
	// 键为 "<接口名>|<节点公钥>"。
	//
	// 为什么需要它：内核不返回口令明文，而我们又必须避免重复下发 ——
	// 重新下发口令会触发内核 wg_noise_expire_current_peer_keypairs()，
	// 销毁该节点当前的会话密钥，造成掉线。用指纹判断即可做到
	// 「口令变了才下发，没变一次都不碰」。
	PskFingerprints map[string]string `json:"psk_fingerprints,omitempty"`
	// NATRuleFingerprint 是当前生效的内网访问（NAT 转发）配置指纹。
	// 指纹一致时不再重建规则，避免规则抖动。
	NATRuleFingerprint string `json:"nat_fingerprint,omitempty"`
	// NATRuleSources / NATRuleWANs 记录当前生效的源网段与出口网卡，用于界面展示与诊断。
	NATRuleSources []string `json:"nat_sources,omitempty"`
	NATRuleWANs    []string `json:"nat_wans,omitempty"`
	// NATSwitch 记录是否有连接打开了「内网访问」开关。
	//
	// 「开关打开」由用户决定，「规则是否真的生效」取决于环境条件（例如能否探测到出口网卡）。
	// 两者分开记录，界面才能一句话说清「开关是开着的，卡在了哪一层」，
	// 而不是让用户对着一个其实已经打开的开关反复检查。
	NATSwitch bool `json:"nat_switch,omitempty"`
	// NATBlocked 记录开关已打开但规则未能下发的原因（为空表示没有受阻）。
	NATBlocked string `json:"nat_blocked,omitempty"`
	// IPForwardEnabled 记录内核转发开关是否由本应用开启。
	// 只记录不还原：还原可能影响机器上其它依赖转发的服务。
	IPForwardEnabled bool `json:"ip_forward_by_us,omitempty"`

	mu        sync.Mutex `json:"-"`
	path      string     `json:"-"`
	lastSaved []byte     `json:"-"`
}

// LoadState 读取状态文件；不存在时返回空状态。
func LoadState(path string) *State {
	st := &State{path: path}
	raw, err := os.ReadFile(path)
	if err != nil {
		return st
	}
	_ = json.Unmarshal(raw, st)
	st.path = path
	return st
}

// Save 原子写入状态文件。
//
// 内容与上次写入完全一致时直接返回：收敛循环每 10 秒调用一次，
// 稳态下不该持续产生磁盘写入。
func (s *State) Save() error {
	if s.path == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if bytes.Equal(raw, s.lastSaved) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o770); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o640); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}
	s.lastSaved = raw
	return nil
}

// MarkManaged 记录一个由本应用创建的接口。
func (s *State) MarkManaged(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, n := range s.ManagedInterfaces {
		if n == name {
			return
		}
	}
	s.ManagedInterfaces = append(s.ManagedInterfaces, name)
	sort.Strings(s.ManagedInterfaces)
}

// UnmarkManaged 移除记录（接口已不存在时调用）。
func (s *State) UnmarkManaged(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.ManagedInterfaces[:0]
	for _, n := range s.ManagedInterfaces {
		if n != name {
			out = append(out, n)
		}
	}
	s.ManagedInterfaces = out
}

// IsManaged 判断接口是否由本应用创建。
func (s *State) IsManaged(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, n := range s.ManagedInterfaces {
		if n == name {
			return true
		}
	}
	return false
}

// ManagedCopy 返回受管接口列表副本。
func (s *State) ManagedCopy() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.ManagedInterfaces))
	copy(out, s.ManagedInterfaces)
	return out
}

// MarkPolicyRoute 记录一条由本应用下发的策略路由。
func (s *State) MarkPolicyRoute(pr PolicyRoute) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.ManagedPolicyRoutes {
		if s.ManagedPolicyRoutes[i].Dev == pr.Dev && s.ManagedPolicyRoutes[i].CIDR == pr.CIDR {
			return
		}
	}
	s.ManagedPolicyRoutes = append(s.ManagedPolicyRoutes, pr)
	sort.Slice(s.ManagedPolicyRoutes, func(i, j int) bool {
		if s.ManagedPolicyRoutes[i].Dev != s.ManagedPolicyRoutes[j].Dev {
			return s.ManagedPolicyRoutes[i].Dev < s.ManagedPolicyRoutes[j].Dev
		}
		return s.ManagedPolicyRoutes[i].CIDR < s.ManagedPolicyRoutes[j].CIDR
	})
}

// UnmarkPolicyRoute 移除策略路由记录（条目已从内核删除时调用）。
func (s *State) UnmarkPolicyRoute(dev, cidr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.ManagedPolicyRoutes[:0]
	for _, pr := range s.ManagedPolicyRoutes {
		if pr.Dev == dev && pr.CIDR == cidr {
			continue
		}
		out = append(out, pr)
	}
	s.ManagedPolicyRoutes = out
}

// HasPolicyRoute 判断指定连接的目标网段是否已记录在案。
func (s *State) HasPolicyRoute(dev, cidr string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, pr := range s.ManagedPolicyRoutes {
		if pr.Dev == dev && pr.CIDR == cidr {
			return true
		}
	}
	return false
}

// PolicyRoutesCopy 返回全部策略路由记录副本。
func (s *State) PolicyRoutesCopy() []PolicyRoute {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]PolicyRoute, len(s.ManagedPolicyRoutes))
	copy(out, s.ManagedPolicyRoutes)
	return out
}

// PolicyRoutesFor 返回某条连接名下的策略路由记录副本。
func (s *State) PolicyRoutesFor(dev string) []PolicyRoute {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]PolicyRoute, 0, len(s.ManagedPolicyRoutes))
	for _, pr := range s.ManagedPolicyRoutes {
		if pr.Dev == dev {
			out = append(out, pr)
		}
	}
	return out
}

// ---------------------------------------------------------------- 口令指纹

// PskFingerprint 返回已记录的二次加密口令指纹，未记录时返回空串。
func (s *State) PskFingerprint(device, publicKey string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.PskFingerprints[pskStateKey(device, publicKey)]
}

// SetPskFingerprint 记录口令指纹，供下一轮收敛判断是否需要重新下发。
func (s *State) SetPskFingerprint(device, publicKey, fingerprint string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.PskFingerprints == nil {
		s.PskFingerprints = map[string]string{}
	}
	s.PskFingerprints[pskStateKey(device, publicKey)] = fingerprint
}

// DropPskFingerprint 移除单个节点的口令指纹（节点被删除时调用）。
func (s *State) DropPskFingerprint(device, publicKey string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.PskFingerprints, pskStateKey(device, publicKey))
}

// DropPskFingerprints 移除某条接口的全部口令指纹（接口被删除或卸载时调用）。
func (s *State) DropPskFingerprints(device string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	prefix := device + "|"
	for k := range s.PskFingerprints {
		if strings.HasPrefix(k, prefix) {
			delete(s.PskFingerprints, k)
		}
	}
}

func pskStateKey(device, publicKey string) string {
	return device + "|" + publicKey
}

// pskFingerprint 计算口令指纹。只取 8 字节用于比对：
// 既不泄露口令内容，也不足以用于暴力还原。
func pskFingerprint(psk string) string {
	sum := sha256.Sum256([]byte(psk))
	return hex.EncodeToString(sum[:8])
}

// ---------------------------------------------------------------- 内网访问

// NATFingerprint 返回当前生效的内网访问配置指纹，未启用时为空串。
func (s *State) NATFingerprint() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.NATRuleFingerprint
}

// NATSources 返回当前生效的源网段副本。
func (s *State) NATSources() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.NATRuleSources))
	copy(out, s.NATRuleSources)
	return out
}

// NATWANs 返回当前生效的出口网卡副本。
func (s *State) NATWANs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.NATRuleWANs))
	copy(out, s.NATRuleWANs)
	return out
}

// NATSwitchOn 返回是否有连接打开了内网访问开关。
func (s *State) NATSwitchOn() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.NATSwitch
}

// NATBlockedReason 返回最近一次内网访问未能启用的原因（为空表示没有受阻）。
func (s *State) NATBlockedReason() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.NATBlocked
}

// SetNATState 记录内网访问开关状态与未能启用的原因。
// 收敛循环每 10 秒调用一次，内容不变时 Save 不会产生磁盘写入。
func (s *State) SetNATState(switchedOn bool, blocked string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.NATSwitch = switchedOn
	if switchedOn {
		s.NATBlocked = blocked
		return
	}
	s.NATBlocked = ""
}

// IPForwardByUs 返回内核转发开关是否由本应用开启。
func (s *State) IPForwardByUs() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.IPForwardEnabled
}

// SetIPForwardByUs 记录本应用是否开启过内核转发。
func (s *State) SetIPForwardByUs(v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.IPForwardEnabled = v
}

// SetNAT 记录内网访问规则的当前状态；指纹传空串表示已关闭。
func (s *State) SetNAT(fingerprint string, sources, wans []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.NATRuleFingerprint = fingerprint
	if fingerprint == "" {
		s.NATRuleSources = nil
		s.NATRuleWANs = nil
		return
	}
	s.NATRuleSources = append([]string{}, sources...)
	s.NATRuleWANs = append([]string{}, wans...)
}

// SetBaseline 记录系统默认路由基线（只在首次采集，避免被污染后的状态覆盖）。
func (s *State) SetBaseline(routes []BaselineRoute) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.BaselineTaken {
		return
	}
	s.BaselineDefaults = routes
	s.BaselineTaken = true
}

// Baseline 返回基线副本。
func (s *State) Baseline() []BaselineRoute {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]BaselineRoute, len(s.BaselineDefaults))
	copy(out, s.BaselineDefaults)
	return out
}
