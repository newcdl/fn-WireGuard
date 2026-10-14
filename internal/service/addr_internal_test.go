// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package service

import (
	"strings"
	"testing"

	"fnwg/internal/model"
)

// TestAddrBaseDistinctOffsets 自动分配的网段基准：**跨机去相关**、同机内顺延、始终不出界。
//
// 这是「两台 NAS 的设备地址成对重复」的根治手段：两端各自按序号分配，第 N 条必然同网段，
// 加上按机器随机的基准后，两端撞车的概率从「必然」降到约 1/241。
func TestAddrBaseDistinctOffsets(t *testing.T) {
	// 同一序号、不同基准 → 不同网段（这就是「两台 NAS 不再必然撞车」的依据）
	if a, b := defaultInterfaceAddr(0, 0), defaultInterfaceAddr(7, 0); a == b {
		t.Fatalf("不同基准偏移应给出不同网段，实际都是 %s", a)
	}
	// 同一基准内按序号顺延
	if a, b := defaultInterfaceAddr(3, 0), defaultInterfaceAddr(3, 1); a == b {
		t.Fatalf("同一基准下相邻序号应给出不同网段，实际都是 %s", a)
	}
	// 无论怎么组合都必须落在 10.10.0.0/24 ~ 10.250.0.0/24 内
	for offset := 0; offset <= addrSpan; offset += 17 {
		for _, idx := range []int{0, 1, 5, 240, 999} {
			base := addrBase(offset, idx)
			if base < addrBaseMin || base > addrBaseMax {
				t.Fatalf("基准 %d + 序号 %d 折算出界：10.%d.0.1/24", offset, idx, base)
			}
		}
	}
	// 负数偏移（脏数据）不该崩，也不该出界
	if base := addrBase(-5, 0); base < addrBaseMin || base > addrBaseMax {
		t.Fatalf("负数偏移应被折回区间内，实际 %d", base)
	}
	// 序号也取负数（脏数据）时按 0 处理
	if got, want := addrBase(3, -2), addrBase(3, 0); got != want {
		t.Fatalf("负数序号应按 0 处理，实际 %d / %d", got, want)
	}
}

// TestPickFreeAddrAvoidsReserved 自动分配要避开「另一台 NAS 已占用的网段」。
//
// 这是「新建连接的默认网段正好落在对端已用网段上」的唯一防线：本机内部唯一并不能保证
// 两端不撞车 —— 撞车之后的现象只是「访问不了对端的某几台设备」，用户推不出原因。
func TestPickFreeAddrAvoidsReserved(t *testing.T) {
	offset := 0
	// 不加避免清单时，第一个候选就是它
	first := defaultInterfaceAddr(offset, 0)

	got := pickFreeAddr(nil, 0, offset, []string{first})
	if got == first {
		t.Fatalf("应当避开对端已占用的 %s，实际仍拿到它", first)
	}
	if got != defaultInterfaceAddr(offset, 1) {
		t.Fatalf("避开后应当顺延到下一位 %s，实际 %s", defaultInterfaceAddr(offset, 1), got)
	}

	// 本机已有连接同样要避开：两类清单是叠加的，不是二选一
	others := []model.Interface{{Name: "wg0", Addresses: []string{first}}}
	if got := pickFreeAddr(others, 0, offset, nil); got == first {
		t.Fatalf("本机已有的 %s 也必须避开", first)
	}

	// 清单里的非法项/空项不该让它崩，也不该把候选全挡掉
	if got := pickFreeAddr(nil, 0, offset, []string{"", "不是网段"}); got != first {
		t.Fatalf("无效的避免项不该改变分配结果，实际 %s", got)
	}
}

// TestSanitizeSubnets 对端随邀请带来的清单要宽松解析：跳过非法项，收下合法的。
//
// 它是对方的表述，且老版本没有这一项 —— 宁可少收一条，也不该因此挡住导入。
func TestSanitizeSubnets(t *testing.T) {
	got := sanitizeSubnets([]string{
		" 10.30.0.0/24 ", "10.30.0.0/24", // 去空白 + 去重
		"10.31.5.7/24", // 带主机位 → 掩掉主机位，归一到 10.31.5.0/24
		"0.0.0.0/0",    // 「所有地址」会命中本机每一个连接，必须丢掉
		"", "不是网段",
	})
	want := []string{"10.30.0.0/24", "10.31.5.0/24"}
	if len(got) != len(want) {
		t.Fatalf("应当只留下两条合法网段，实际 %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("第 %d 项应为 %s，实际 %v", i, want[i], got)
		}
	}
	if len(sanitizeSubnets(nil)) != 0 {
		t.Fatal("空清单应返回空")
	}
}

// TestPeerOccupiedNote 提醒必须区分「两端共用的互联网段」与「对端自己的其它网段」：
// 前者由互联本身占用、后者才是本机新建连接时要避开的，两者的处置完全不同。
func TestPeerOccupiedNote(t *testing.T) {
	note := peerOccupiedNote([]string{"10.20.0.0/24"}, []string{"10.30.0.0/24"})
	if note == "" {
		t.Fatal("有内容时不该返回空")
	}
	if !strings.Contains(note, "10.30.0.0/24") || !strings.Contains(note, "避开") {
		t.Fatalf("要说清对端占了哪些网段、以及本机会避开：%s", note)
	}
	if !strings.Contains(note, "10.20.0.0/24") || !strings.Contains(note, "共用") {
		t.Fatalf("共用的互联网段要单独点出来（别在这里挂设备）：%s", note)
	}
	// 单向性是必须说清的边界：对方之后新增的连接不会同步过来
	if !strings.Contains(note, "单向") {
		t.Fatalf("要说清这份清单只是导入那一刻的情况：%s", note)
	}
	if got := peerOccupiedNote(nil, nil); got != "" {
		t.Fatalf("没有内容时不该硬凑一句话，实际：%s", got)
	}
}

// TestOccupiedOverlapNote 对端带来的连接网段清单与本机撞车时要说清（不阻断导入）。
func TestOccupiedOverlapNote(t *testing.T) {
	mine := []model.Interface{
		{Name: "wg0", Addresses: []string{"10.10.0.1/24"}},
		{Name: "wg1", Addresses: []string{"10.11.0.1/24"}},
	}
	if note := occupiedOverlapNote([]string{"10.20.0.0/24"}, mine); note != "" {
		t.Fatalf("不重叠时不该有提示，实际: %s", note)
	}
	note := occupiedOverlapNote([]string{"10.10.0.0/24"}, mine)
	if note == "" || !strings.Contains(note, "wg0") {
		t.Fatalf("撞车时必须点名是哪条连接，实际: %s", note)
	}
	// 只说"撞车"没有意义：必须说清后果（设备互访不通）与怎么改（换网段后重新生成邀请）
	if !strings.Contains(note, "设备") || !strings.Contains(note, "本机专用地址") || !strings.Contains(note, "重新生成") {
		t.Fatalf("提示要说清后果与处理办法，实际: %s", note)
	}
	// 老邀请没有这项：空清单不该产生任何提示
	if note := occupiedOverlapNote(nil, mine); note != "" {
		t.Fatalf("对端没有带清单（老邀请）时不该有提示，实际: %s", note)
	}
}

// TestHostOverlaps 判定「主机地址是否落进对方声明」的细节：只比地址，不把整段当成一台设备。
func TestHostOverlaps(t *testing.T) {
	cases := []struct {
		name  string
		host  string
		other string
		want  bool
	}{
		{"同一个地址", "10.20.0.3/32", "10.20.0.3/32", true},
		{"落在对方声明的网段里", "10.20.0.3/32", "10.20.0.0/24", true},
		{"同网段的另一个地址不算冲突", "10.20.0.3/32", "10.20.0.9/32", false},
		{"完全不相干", "10.20.0.3/32", "192.168.2.0/24", false},
		{"非法输入不报错也不误报", "不是地址", "192.168.2.0/24", false},
		{"非法输入不报错也不误报（另一侧）", "10.20.0.3/32", "不是网段", false},
	}
	for _, c := range cases {
		if got := hostOverlaps(c.host, c.other); got != c.want {
			t.Fatalf("%s：期望 %v，实际 %v", c.name, c.want, got)
		}
	}
}

// TestComparableWithTunnel 比隧道网段更宽的声明不参与冲突判定。
//
// 那是「对端整个地址空间都能进来」这类准入声明（例如把对端内网写成 10.0.0.0/8），
// 本机自己的隧道地址本来就落在它里面 —— 拿它去比会把这条连接上的每台设备都判成冲突。
func TestComparableWithTunnel(t *testing.T) {
	ones := map[int]int{4: 24}
	cases := []struct {
		entry string
		want  bool
	}{
		{"10.20.0.3/32", true},   // 比隧道网段更细：参与比较
		{"10.20.0.0/24", true},   // 与隧道网段一样宽：参与比较
		{"10.0.0.0/8", false},    // 更宽：跳过
		{"0.0.0.0/0", false},     // 更宽：跳过
		{"192.168.2.0/24", true}, // 不比隧道更宽（虽在隧道之外，判定交给上层）
		{"不是网段", false},
	}
	for _, c := range cases {
		if got := comparableWithTunnel(c.entry, ones); got != c.want {
			t.Fatalf("%s：期望 %v，实际 %v", c.entry, c.want, got)
		}
	}
	// 本连接没有该族的网段时不作判断（交给其它校验）
	if !comparableWithTunnel("fd00:9::/64", ones) {
		t.Fatal("本连接没有 v6 网段时不该拦 v6 声明")
	}
}
