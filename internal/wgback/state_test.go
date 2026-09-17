package wgback

import (
	"path/filepath"
	"testing"
)

// 数据面实现的记录必须随状态文件一起落盘：
// 进程重启后要靠它判断「这张网卡是内核建的还是用户态建的」，
// 判错就会去配置一张根本配不上的网卡。
func TestInterfaceBackendSurvivesReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "netstate.json")

	st := LoadState(path)
	st.MarkManaged("wg0")
	// 直接写字面量：状态文件是跨平台格式，不该依赖 Linux 专有的常量，
	// 否则这个用例在开发机（非 Linux）上根本编译不过。
	st.SetInterfaceBackend("wg0", "userspace")
	if err := st.Save(); err != nil {
		t.Fatalf("保存状态失败: %v", err)
	}

	re := LoadState(path)
	if got := re.InterfaceBackend("wg0"); got != "userspace" {
		t.Fatalf("重载后创建者记录丢失: %q", got)
	}
	if !re.IsManaged("wg0") {
		t.Fatal("重载后受管接口记录丢失")
	}
}

// 删除接口时必须一并清掉创建者记录，否则同一名字再次被创建时
// 会误判为「数据面变了」而白白重建一次。
func TestUnmarkManagedDropsBackendRecord(t *testing.T) {
	st := LoadState(filepath.Join(t.TempDir(), "netstate.json"))
	st.MarkManaged("wg1")
	st.SetInterfaceBackend("wg1", "kernel")

	st.UnmarkManaged("wg1")
	if got := st.InterfaceBackend("wg1"); got != "" {
		t.Fatalf("删除后仍残留创建者记录: %q", got)
	}
	if st.IsManaged("wg1") {
		t.Fatal("删除后仍标记为受管")
	}
	// 未记录过的接口读出来是空串，代表「升级前创建的历史接口」——
	// 调用方据此不做重建，保持与旧版本一致的行为。
	if got := st.InterfaceBackend("never-seen"); got != "" {
		t.Fatalf("未记录的接口应返回空串，实际 %q", got)
	}
}
