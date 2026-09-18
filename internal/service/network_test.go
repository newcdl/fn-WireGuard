// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 newcdl <newcdl@163.com>

package service

import (
	"testing"

	"fnwg/internal/model"
)

// TestCidrCoversAll 验证「设备通行范围是否包含家里网段」的判定。
//
// 这是内网访问诊断的关键一步：设备的通行范围里没有家里网段时，
// 它根本不会把这些流量送进隧道，现象和「转发没配好」完全一样。
// 判定过松会让诊断误报「通过」，用户就会去查错的方向。
func TestCidrCoversAll(t *testing.T) {
	cases := []struct {
		name    string
		allowed []string
		home    []string
		want    bool
	}{
		{"完全一致", []string{"192.168.3.0/24"}, []string{"192.168.3.0/24"}, true},
		{"更宽的网段覆盖更窄的", []string{"192.168.0.0/16"}, []string{"192.168.3.0/24"}, true},
		{"更窄的网段不构成覆盖", []string{"192.168.3.128/25"}, []string{"192.168.3.0/24"}, false},
		{"完全不含", []string{"10.10.0.0/24"}, []string{"192.168.3.0/24"}, false},
		{"多个家里网段缺一不可", []string{"192.168.3.0/24"}, []string{"192.168.3.0/24", "172.16.0.0/16"}, false},
		{"不同协议族不算覆盖", []string{"fd00::/64"}, []string{"192.168.3.0/24"}, false},
		{"家里网段为空时视为通过", []string{"10.0.0.0/8"}, nil, true},
		{"写法带主机位也能识别", []string{"192.168.3.7/24"}, []string{"192.168.3.0/24"}, true},
	}
	for _, c := range cases {
		if got := cidrCoversAll(c.allowed, c.home); got != c.want {
			t.Errorf("%s: 期望 %v，实际 %v（allowed=%v home=%v）", c.name, c.want, got, c.allowed, c.home)
		}
	}
}

// TestDescribePeer 节点标识优先用名称，没有名称时退化为编号。
func TestDescribePeer(t *testing.T) {
	if got := describePeer(&model.Peer{ID: 3, Name: "我的手机"}); got != "我的手机" {
		t.Fatalf("有名称时应使用名称，实际: %s", got)
	}
	if got := describePeer(&model.Peer{ID: 3}); got != "#3" {
		t.Fatalf("无名称时应退化为编号，实际: %s", got)
	}
}
