package wgback

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
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
	// BaselineDefaults 首次运行时的系统默认路由（仅快照，不修改系统配置）。
	BaselineDefaults []BaselineRoute `json:"baseline_default_routes"`
	// BaselineTaken 是否已采集过基线。
	BaselineTaken bool `json:"baseline_taken"`

	mu   sync.Mutex `json:"-"`
	path string     `json:"-"`
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
func (s *State) Save() error {
	if s.path == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(s.path), 0o770); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
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
