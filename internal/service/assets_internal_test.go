// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小 newcommer <newxsz@163.com>

package service

import (
	"testing"
	"time"

	"fnwg/internal/model"
)

// TestMergeAssetsNewDevice 新设备判定是这功能的要害：
// 漏报 = 陌生人进来没提醒，误报 = 每次巡检都报警、用户很快把提醒关掉（那就等于没有）。
func TestMergeAssetsNewDevice(t *testing.T) {
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.Local)
	day := now.Add(-24 * time.Hour)

	assets, fresh := mergeAssets(nil, []model.LANDevice{{IP: "192.168.1.10", MAC: "aa:bb"}}, now, nil, nil)
	if len(fresh) != 1 || len(assets) != 1 {
		t.Fatalf("第一次见到应当既入账又算新设备：%+v / %+v", assets, fresh)
	}
	if !assets[0].FirstSeen.Equal(now) || !assets[0].LastSeen.Equal(now) {
		t.Fatal("首次与最近出现都应记成这次观测时刻")
	}
	if assets[0].SeenDays != 1 {
		t.Fatalf("首次出现的天数应为 1：%d", assets[0].SeenDays)
	}

	// 再见一次：不再算新设备，最近出现更新
	assets, fresh = mergeAssets(assets, []model.LANDevice{{IP: "192.168.1.10", MAC: "aa:bb"}}, now.Add(time.Hour), nil, nil)
	if len(fresh) != 0 {
		t.Fatalf("见过的设备不该重复算新设备：%+v", fresh)
	}
	if !assets[0].LastSeen.After(now) {
		t.Fatal("最近出现应当更新")
	}

	// 陌生设备：必须被认出来
	_, fresh = mergeAssets(assets, []model.LANDevice{{IP: "192.168.1.99"}}, now.Add(2*time.Hour), nil, nil)
	if len(fresh) != 1 || fresh[0].IP != "192.168.1.99" {
		t.Fatalf("陌生设备应当被识别为新设备：%+v", fresh)
	}

	// 用户已确认过的设备：记录里的 Known 要保留（合并不能把它抹掉）
	assets[0].Known = true
	assets, _ = mergeAssets(assets, []model.LANDevice{{IP: "192.168.1.10"}}, day, nil, nil)
	if !assets[0].Known {
		t.Fatal("合并时不能丢掉「已知」标记，否则用户确认过的设备会反复提醒")
	}
}
