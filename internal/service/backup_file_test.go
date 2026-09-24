// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package service_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"fnwg/internal/service"
	"fnwg/internal/store"
)

// TestBackupFilenamesDoNotCollide 锁定「同一秒内的两次备份不能撞名」。
//
// 备份文件名精确到秒，撞名时的老做法是直接覆盖：数据库里留下两条记录指向同一个文件，
// 较早那次的内容就此消失，记录的校验值也与文件对不上——而列表里两条看起来都好好的，
// 直到某天真的要用那份备份才发现内容不对。这在界面上很容易触发：连点两次「立即备份」。
func TestBackupFilenamesDoNotCollide(t *testing.T) {
	svc, _ := newTestEnv(t)
	ctx := context.Background()
	actor := service.Actor{Username: "tester"}
	dir := t.TempDir()

	// 先把「这一秒」与「下一秒」可能用到的名字占掉，逼出「追加后缀」那条分支。
	// 这样无论两次调用是否落在同一秒，被测行为都是确定的。
	now := time.Now()
	for _, ts := range []time.Time{now, now.Add(time.Second)} {
		name := fmt.Sprintf("fn-wireguard-backup-%s.json", ts.Format("20060102-150405"))
		if err := os.WriteFile(filepath.Join(dir, name), []byte("occupied"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	first, err := svc.CreateBackup(ctx, dir, "第一次", actor)
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.CreateBackup(ctx, dir, "第二次", actor)
	if err != nil {
		t.Fatal(err)
	}
	if first.Filename == second.Filename {
		t.Fatalf("同一秒的两次备份不应共用文件名：%s", first.Filename)
	}
	// 每条记录对应的文件都要在，且内容与记录的校验值一致 —— 这正是撞名时会坏掉的东西
	for _, rec := range []*store.BackupRecord{first, second} {
		raw, err := os.ReadFile(filepath.Join(dir, rec.Filename))
		if err != nil {
			t.Fatalf("记录 %s 对应的文件不存在：%v", rec.Filename, err)
		}
		sum := sha256.Sum256(raw)
		if hex.EncodeToString(sum[:]) != rec.SHA256 {
			t.Fatalf("记录 %s 的校验值与文件内容不一致", rec.Filename)
		}
	}
}
