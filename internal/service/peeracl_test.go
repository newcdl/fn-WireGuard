// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package service_test

import (
	"context"
	"strings"
	"testing"

	"fnwg/internal/model"
	"fnwg/internal/service"
)

// TestPeerLANAccessRoundTrip 设备的内网访问范围要能存下去、读回来，并且取值被归一化。
//
// 这是「按设备限制内网目标」的入口：设备侧的通行范围只是建议，服务端规则才是约束。
// 两个归一化要点都钉在这里：restrict 的目标去重并规范成统一写法；
// inherit / deny 下目标一律清空 —— 留着会让界面出现一堆用不上的目标，
// 还会让人以为 deny 也允许它们。
func TestPeerLANAccessRoundTrip(t *testing.T) {
	svc, st := newTestEnv(t)
	ctx := context.Background()
	actor := service.Actor{Username: "tester"}
	enabled := true
	it, err := svc.CreateInterface(ctx, service.CreateInterfaceInput{Name: "wg0", Enabled: &enabled}, actor)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name        string
		policy      string
		targets     []string
		wantPolicy  string
		wantTargets int
	}{
		{"不填即随连接", "", nil, model.LANPolicyInherit, 0},
		{"显式随连接时目标被清空", model.LANPolicyInherit, []string{"192.168.1.10"}, model.LANPolicyInherit, 0},
		{"禁止访问内网时目标被清空", model.LANPolicyDeny, []string{"192.168.1.10"}, model.LANPolicyDeny, 0},
		{"只允许指定目标（去重）", model.LANPolicyRestrict,
			[]string{"192.168.1.10:445", " 192.168.1.0/24 ", "192.168.1.10:445"},
			model.LANPolicyRestrict, 2},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, err := svc.CreatePeer(ctx, service.PeerInput{
				InterfaceID:  it.ID,
				Name:         "phone",
				GenerateKeys: true,
				LANPolicy:    c.policy,
				LANTargets:   c.targets,
			}, actor)
			if err != nil {
				t.Fatal(err)
			}
			// 从库里读回来（验证存储往返，而不是只看内存里的对象）
			got, err := st.GetPeer(ctx, p.ID)
			if err != nil {
				t.Fatal(err)
			}
			if got.LANPolicy != c.wantPolicy {
				t.Fatalf("策略应为 %s，实际 %s", c.wantPolicy, got.LANPolicy)
			}
			if len(got.LANTargets) != c.wantTargets {
				t.Fatalf("目标条数应为 %d，实际 %v", c.wantTargets, got.LANTargets)
			}
			if i == 3 {
				if got.LANTargets[0] != "192.168.1.10:445" || got.LANTargets[1] != "192.168.1.0/24" {
					t.Fatalf("目标应去重且规范成统一写法：%v", got.LANTargets)
				}
			}
			// 更新路径也要能改回去（面板里改策略是最常见的操作）
			if i == 3 {
				// 更新是「全量提交」：界面提交的是整份表单，这里照做（只改策略、其余原样带回）
				cur, err := st.GetPeer(ctx, p.ID)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := svc.UpdatePeer(ctx, p.ID, service.PeerInput{
					InterfaceID: cur.InterfaceID, Name: cur.Name, RouteMode: cur.RouteMode,
					ClientAllowedIPs: cur.ClientAllowedIPs, AllowedIPs: cur.AllowedIPs,
					LANPolicy: model.LANPolicyDeny,
				}, actor); err != nil {
					t.Fatal(err)
				}
				again, err := st.GetPeer(ctx, p.ID)
				if err != nil {
					t.Fatal(err)
				}
				if again.LANPolicy != model.LANPolicyDeny || len(again.LANTargets) != 0 {
					t.Fatalf("改成禁止访问后策略与目标都要更新：%+v", again)
				}
			}
		})
	}
}

// TestPeerLANAccessRejects 保存期的校验：这些取值一旦落库，规则就"看着配了、其实不对"。
func TestPeerLANAccessRejects(t *testing.T) {
	svc, _ := newTestEnv(t)
	ctx := context.Background()
	actor := service.Actor{Username: "tester"}
	enabled := true
	it, err := svc.CreateInterface(ctx, service.CreateInterfaceInput{Name: "wg0", Enabled: &enabled}, actor)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		policy  string
		targets []string
		words   string
	}{
		{"策略取值乱写", "sometimes", nil, "取值不正确"},
		{"只允许指定目标却没填", model.LANPolicyRestrict, nil, "至少要填一个目标"},
		{"目标不是地址", model.LANPolicyRestrict, []string{"办公室"}, "不是合法的 IPv4"},
		{"目标写成全网", model.LANPolicyRestrict, []string{"0.0.0.0/0"}, "0.0.0.0/0"},
		{"端口越界", model.LANPolicyRestrict, []string{"192.168.1.10:99999"}, "端口"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := svc.CreatePeer(ctx, service.PeerInput{
				InterfaceID: it.ID, Name: "phone", GenerateKeys: true,
				LANPolicy: c.policy, LANTargets: c.targets,
			}, actor)
			if err == nil || !strings.Contains(err.Error(), c.words) {
				t.Fatalf("应被拒绝并说明原因（含 %q），实际：%v", c.words, err)
			}
		})
	}
}
