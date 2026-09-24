// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package service

import "testing"

// TestDeviceKindValidation 类型枚举的校验：只认清单里的值。
//
// 这一层必须严格：配置会一路变成图上的图标，收下不认识的值只会让图标变成兜底样式，
// 用户还以为自己配成功了。
func TestDeviceKindValidation(t *testing.T) {
	if !validDeviceKind("router") || !validDeviceKind("printer") {
		t.Fatal("清单里的值应当被接受")
	}
	if validDeviceKind("") || validDeviceKind("Router") || validDeviceKind("摄像头") {
		t.Fatal("空值、大小写不一致、中文标签都不该被当作合法值")
	}
	if DeviceKindLabel("router") == "router" {
		t.Fatal("已知类型应当翻成中文")
	}
	if DeviceKindLabel("unknown-kind") != "unknown-kind" {
		t.Fatal("未知值原样返回，界面不能出现空标签")
	}
	// 清单里不能有重复值：重复会让下拉出现两项、且存的是什么说不清
	seen := map[string]bool{}
	for _, o := range DeviceKindOptions {
		if seen[o.Value] {
			t.Fatalf("类型值重复：%s", o.Value)
		}
		seen[o.Value] = true
		if o.Label == "" {
			t.Fatalf("类型 %s 缺中文标签", o.Value)
		}
	}
}
