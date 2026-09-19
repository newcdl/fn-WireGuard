// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package service_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fnwg/internal/model"
	"fnwg/internal/service"
)

// 日程判定的边界：刚打开开关不补跑、到点会跑、同一日程点不重复、错过会补一次、
// 关闭时一律不跑。这几条错一条的表现都是「备份多了一份/少了一份」，而用户很难察觉。
func TestBackupPlanDueSchedule(t *testing.T) {
	dir := t.TempDir()
	daily := service.BackupPlan{Enabled: true, Freq: service.FreqDaily, At: "03:30", Keep: 7, Dir: dir}
	// 基准：下午三点启用
	since := time.Date(2026, 9, 19, 15, 0, 0, 0, time.Local)

	if daily.Due(time.Date(2026, 9, 19, 15, 5, 0, 0, time.Local), time.Time{}, since) {
		t.Fatal("刚打开开关不应立刻补跑（用户会莫名多一份计划外备份）")
	}
	due := time.Date(2026, 9, 20, 3, 31, 0, 0, time.Local)
	if !daily.Due(due, time.Time{}, since) {
		t.Fatal("到点后应当执行")
	}
	if daily.Due(time.Date(2026, 9, 20, 4, 0, 0, 0, time.Local),
		time.Date(2026, 9, 20, 3, 30, 0, 0, time.Local), since) {
		t.Fatal("同一个日程点不应重复执行")
	}
	if !daily.Due(time.Date(2026, 9, 21, 9, 0, 0, 0, time.Local),
		time.Date(2026, 9, 20, 3, 30, 0, 0, time.Local), since) {
		t.Fatal("NAS 关机错过一次后，开机应当补跑（少一份备份比晚一点更糟）")
	}
	off := daily
	off.Enabled = false
	if off.Due(due, time.Time{}, since) {
		t.Fatal("关闭时不应执行")
	}

	// 每周一 04:00（2026-09-21 是周一，09-20 是周日）。
	// 基准取 09-15（周二，即「上一个周一之后」），这样周一 09-14 那场不算数。
	weekly := service.BackupPlan{Enabled: true, Freq: service.FreqWeekly, At: "04:00", Weekday: 1, Keep: 3, Dir: dir}
	base := time.Date(2026, 9, 15, 0, 0, 0, 0, time.Local)
	if weekly.Due(time.Date(2026, 9, 20, 23, 0, 0, 0, time.Local), time.Time{}, base) {
		t.Fatal("周日晚上还没到周一，不应执行")
	}
	if !weekly.Due(time.Date(2026, 9, 21, 4, 30, 0, 0, time.Local), time.Time{}, base) {
		t.Fatal("周一 04:00 之后应当执行")
	}
	// 上一场（周一 09-14）在生效之前，因此即使一直没跑过也不该补
	if weekly.Due(time.Date(2026, 9, 15, 12, 0, 0, 0, time.Local), time.Time{}, base) {
		t.Fatal("生效之前的日程不该被当成「错过」")
	}
	// 生效之后真的错过一场（周一 09-21），过了那天再开机也要补一次
	if !weekly.Due(time.Date(2026, 9, 22, 10, 0, 0, 0, time.Local), time.Time{}, base) {
		t.Fatal("生效之后错过的日程应当补跑")
	}

	// 下次执行时间：当天还没到就是今天，过了就是明天
	if next, ok := daily.NextDue(time.Date(2026, 9, 20, 1, 0, 0, 0, time.Local)); !ok ||
		!next.Equal(time.Date(2026, 9, 20, 3, 30, 0, 0, time.Local)) {
		t.Fatalf("当天未到点时应显示今天，实际 %v", next)
	}
	if next, ok := daily.NextDue(time.Date(2026, 9, 20, 4, 0, 0, 0, time.Local)); !ok ||
		!next.Equal(time.Date(2026, 9, 21, 3, 30, 0, 0, time.Local)) {
		t.Fatalf("当天已过点时应显示明天，实际 %v", next)
	}
	if _, ok := off.NextDue(due); ok {
		t.Fatal("关闭时不该给出「下次执行时间」——那会让人以为它还会跑")
	}
}

// 执行一次要真的写出文件、收紧到保留份数，并且**只**动自己写下的文件。
// 目标目录是用户自己的目录，里面有别的东西很正常（照片、文档、别的备份）。
func TestBackupPlanRunWritesAndPrunes(t *testing.T) {
	svc, st := newTestEnv(t)
	ctx := context.Background()
	actor := service.Actor{Username: "tester", SrcIP: "127.0.0.1"}

	it, err := svc.CreateInterface(ctx, service.CreateInterfaceInput{
		Name: "wg0", Addresses: []string{"10.10.0.1/24"}, Enabled: boolPtr(true),
	}, actor)
	if err != nil {
		t.Fatal(err)
	}

	target := t.TempDir()
	own := t.TempDir()
	foreign := filepath.Join(target, "我的照片.jpg")
	if err := os.WriteFile(foreign, []byte("not a backup"), 0o600); err != nil {
		t.Fatal(err)
	}
	// 前缀一样但后缀不对：同样不能被删（清理只认完整规则）
	nearMiss := filepath.Join(target, service.BackupPlanFilePrefix+"old.txt")
	if err := os.WriteFile(nearMiss, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}

	runner := service.NewBackupPlanRunner(st, "0.9.3-test", service.BackupPlanEnv{
		OwnDir:         own,
		AuthorizedDirs: []string{target},
	}, nil)
	plan := service.BackupPlan{Enabled: true, Freq: service.FreqDaily, At: "03:30", Keep: 3, Dir: target}
	// 先存配置：Status 读的是落库的配置，不存就等于「用户还没设置过」。
	if err := runner.SavePlan(ctx, plan, time.Date(2026, 9, 18, 0, 0, 0, 0, time.Local), actor); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		now := time.Date(2026, 9, 19, 3, 30+i, 0, 0, time.Local)
		if state := runner.RunNow(ctx, plan, now, false, actor); !state.OK {
			t.Fatalf("第 %d 次备份失败：%s", i+1, state.Error)
		}
	}

	files, err := service.ListBackupPlanFiles(target)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 3 {
		t.Fatalf("保留 3 份，实际留下 %d 份", len(files))
	}
	for _, keep := range []string{foreign, nearMiss} {
		if _, err := os.Stat(keep); err != nil {
			t.Fatalf("不属于本应用的文件被误删了：%s", keep)
		}
	}

	// 写出来的必须是一份能用的备份：交给导入路径验证（它会校验内容结构）
	raw, err := service.ReadBackupPlanFile(target, files[0].Name)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := svc.ImportBackup(ctx, own, raw, files[0].Name, "测试导入", actor)
	if err != nil {
		t.Fatalf("计划备份写出的文件无法被导入：%v", err)
	}
	payload, _, err := svc.LoadBackupPayload(ctx, own, rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, got := range payload.Interfaces {
		if got.ID == it.ID {
			found = true
		}
	}
	if !found {
		t.Fatal("备份内容里应当包含现有连接")
	}

	// 最近的执行结果要落在状态里，供界面显示「上次成功于 …」
	status := runner.Status(ctx, time.Date(2026, 9, 19, 4, 0, 0, 0, time.Local))
	if status.Last == nil || !status.Last.OK || status.Last.File != files[0].Name {
		t.Fatalf("最近一次结果未正确记录：%+v", status.Last)
	}
	// 副本列表与「能不能写」由执行写入的一方给出（这里就是本进程；真机上是特权代理）：
	// 状态本身只带配置与最近一次结果，事实走 InspectBackupDir。
	info, err := runner.InspectBackupDir(ctx, status.ResolvedDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(info.Files) != 3 || !info.OK {
		t.Fatalf("副本列表或目录可用性不对：%d 份 / OK=%v / %s", len(info.Files), info.OK, info.Note)
	}

	// 只接受纯文件名：带上路径成分就能读到目标目录之外的文件
	if _, err := service.ReadBackupPlanFile(target, "../"+files[0].Name); err == nil {
		t.Fatal("含路径成分的文件名必须被拒绝")
	}
	if _, err := service.ReadBackupPlanFile(target, "我的照片.jpg"); err == nil {
		t.Fatal("非本应用写下的文件必须被拒绝")
	}
}

// 目标目录的校验分两类，混在一起就会出「自相矛盾」的提示：
//   - 政策（这个位置允不允许当目标）：必须在用户授权的目录里、不能放在应用自己的数据目录里；
//   - 事实（那个位置现在写不写得进去）：必须由**真正执行写入的进程**去问 —— 我们这里是特权代理。
//
// 授权那一条是飞牛特有的：应用碰不了没被授权的目录，用户手填一个「看着对」的路径，
// 结果只会是开关打开、每天失败一次。所以保存时就要拦住，并给出「去哪儿授权」这种能照着做的提示。
func TestBackupPlanTargetValidation(t *testing.T) {
	own := t.TempDir()
	auth := t.TempDir()
	env := service.BackupPlanEnv{OwnDir: own, AuthorizedDirs: []string{auth}}

	if err := service.CheckTargetPolicy("backup", env, false); err == nil {
		t.Fatal("相对路径应当被拒绝")
	}
	if err := service.CheckTargetPolicy(filepath.Join(own, "sub"), env, false); err == nil {
		t.Fatal("落在应用自己数据目录里的目标应当被拒绝（源与备份会在同一处一起丢）")
	}
	// 但界面上确实给了「应用自己的备份目录」这个选项：用户显式选它时是合法的
	//（代价是它与源数据同盘，界面会把这一点写出来）。
	if err := service.CheckTargetPolicy(own, env, true); err != nil {
		t.Fatalf("显式选择应用自己的备份目录时应当放行：%v", err)
	}
	// 它的子目录仍然不行：只有「就是那个目录本身」才在允许范围内
	if err := service.CheckTargetPolicy(filepath.Join(own, "sub"), env, true); err == nil {
		t.Fatal("应用自己数据目录的子目录仍应被拒绝")
	}
	// 不在授权清单里：要拒绝，并把可选范围说出来
	if err := service.CheckTargetPolicy(filepath.Join(t.TempDir(), "backup"), env, false); err == nil ||
		!strings.Contains(err.Error(), "已授权") {
		t.Fatalf("未授权的目录应当被拒绝并说明可选范围，实际：%v", err)
	}
	// 一个授权目录都没有：这是用户第一次进来时最常见的样子，必须告诉他去哪儿授权
	noAuth := service.BackupPlanEnv{OwnDir: own}
	if err := service.CheckTargetPolicy(filepath.Join(auth, "backup"), noAuth, false); err == nil ||
		!strings.Contains(err.Error(), "授权") {
		t.Fatalf("没有授权目录时应当提示到飞牛里授权，实际：%v", err)
	}
	// 政策之外还要真写一次探针：授权目录里的子目录不必先去文件管理里建，校验时会建出来
	sub := filepath.Join(auth, "fn-wireguard-backup")
	if err := service.CheckBackupTarget(sub, env, false); err != nil {
		t.Fatalf("授权目录内的子目录应当可用：%v", err)
	}
	if st, err := os.Stat(sub); err != nil || !st.IsDir() {
		t.Fatal("校验通过后子目录应当已经存在")
	}
	// 指向一个已存在的文件：不是文件夹
	file := filepath.Join(auth, "a.json")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := service.CheckBackupTarget(file, env, false); err == nil {
		t.Fatal("指向文件的路径应当被拒绝")
	}
	// 开发模式：本地没有飞牛的授权环境变量，不做授权校验（可写探测仍然照做）
	devEnv := service.BackupPlanEnv{OwnDir: own, Dev: true}
	if err := service.CheckBackupTarget(filepath.Join(t.TempDir(), "dev-backup"), devEnv, false); err != nil {
		t.Fatalf("开发模式不应要求授权目录：%v", err)
	}
	// 但本地把飞牛的授权变量导出来调试时，就按真实口径校验——否则本地测通、上机才发现写不进去
	devWithAuth := service.BackupPlanEnv{OwnDir: own, Dev: true, AuthorizedDirs: []string{auth}}
	if err := service.CheckBackupTarget(filepath.Join(t.TempDir(), "outside"), devWithAuth, false); err == nil {
		t.Fatal("有授权清单时，清单之外的路径即便在开发模式也应被拒绝")
	}
	// 政策与事实分开：不可写的目录政策上没问题、探测必须拦下（root 会绕开权限位，只对非 root 断言）。
	//
	// 这一对断言是这次改动的核心：**界面层只做政策，探测由代理做**。
	// 两者混在一起时，界面进程的权限会被当成备份能否成功的依据，于是真机上出现过
	// 「目录在授权列表里、界面却说不可写，而按日程的备份其实写得好好的」。
	if os.Getuid() != 0 {
		ro := filepath.Join(auth, "ro")
		if err := os.MkdirAll(ro, 0o500); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = os.Chmod(ro, 0o700) }()
		if err := service.CheckTargetPolicy(ro, env, false); err != nil {
			t.Fatalf("只读目录在政策上没问题（挡不挡它取决于谁在写）：%v", err)
		}
		if err := service.CheckBackupTarget(ro, env, false); err == nil {
			t.Fatal("不可写的目录必须被探测拦下——否则第一次备份失败时用户只能猜")
		}
	}
}

// 保存与执行的两条路：
//   - 启用时目标目录不可用必须报错（否则开关是假打开的）；
//   - 关闭时不该强求目录（用户可以先把开关关掉、以后再配）；
//   - 通用设置接口不能成为绕过校验的后门。
func TestBackupPlanSaveAndRunIfDue(t *testing.T) {
	svc, st := newTestEnv(t)
	ctx := context.Background()
	actor := service.Actor{Username: "tester"}
	own := t.TempDir()
	// 用户授权给本应用的目录（飞牛里选的），计划备份只能往这里面写。
	auth := t.TempDir()
	runner := service.NewBackupPlanRunner(st, "test", service.BackupPlanEnv{
		OwnDir:         own,
		AuthorizedDirs: []string{auth},
	}, nil)
	since := time.Date(2026, 9, 19, 15, 0, 0, 0, time.Local)

	// 目标目录不在授权清单里 → 启用时必须被拒绝
	broken := service.BackupPlan{
		Enabled: true, Freq: service.FreqDaily, At: "03:30", Keep: 7,
		Dir: filepath.Join(t.TempDir(), "nope"),
	}
	if err := runner.SavePlan(ctx, broken, since, actor); err == nil {
		t.Fatal("目标目录不在已授权目录里时不应保存成功")
	}
	off := broken
	off.Enabled = false
	if err := runner.SavePlan(ctx, off, since, actor); err != nil {
		t.Fatalf("关闭状态应当允许保存（目录以后再说）：%v", err)
	}
	// 越界的保留份数别想存进去
	if err := runner.SavePlan(ctx, service.BackupPlan{
		Enabled: false, Freq: service.FreqDaily, At: "03:30", Keep: 0, Dir: "",
	}, since, actor); err == nil {
		t.Fatal("保留份数越界应当被拒绝")
	}

	// 授权目录里的子目录直接可用（界面选的是「授权目录 + 子目录名」），到点执行一次后不再重复
	good := service.BackupPlan{
		Enabled: true, Freq: service.FreqDaily, At: "03:30", Keep: 2,
		Dir: filepath.Join(auth, "fn-wireguard-backup"),
	}
	if err := runner.SavePlan(ctx, good, since, actor); err != nil {
		t.Fatal(err)
	}
	due := time.Date(2026, 9, 20, 3, 31, 0, 0, time.Local)
	ran, ok, reason := runner.RunIfDue(ctx, due)
	if !ran || !ok {
		t.Fatalf("到点应当执行且成功，实际 ran=%v ok=%v reason=%s", ran, ok, reason)
	}
	if ran, _, _ := runner.RunIfDue(ctx, due.Add(30*time.Minute)); ran {
		t.Fatal("同一日程点不应重复执行")
	}

	// 已经启用、只是改时间：目标目录此刻不可写也应当能保存。
	// 挡下来并不能改变「它本来就是坏的」，只会让用户在外接盘暂时不在时连配置都改不了。
	if os.Getuid() != 0 {
		if err := os.Chmod(good.Dir, 0o500); err != nil {
			t.Fatal(err)
		}
		later := good
		later.At = "04:30"
		if err := runner.SavePlan(ctx, later, since, actor); err != nil {
			t.Fatalf("只改时刻不该被「目录此刻不可写」挡住：%v", err)
		}
		// 但换目录要重新探测：换了目录等于重新承诺一次「写到那儿」
		moved := later
		moved.Dir = filepath.Join(auth, "another")
		if err := runner.SavePlan(ctx, moved, since, actor); err != nil {
			t.Fatalf("换个可用目录应当能保存：%v", err)
		}
		_ = os.Chmod(good.Dir, 0o700)
	}

	// 通用设置接口是另一条路，必须挡住（它做不了整体校验，也绕过目录探测）
	if err := svc.SetSettings(ctx, map[string]string{service.SettingBackupPlan: `{"enabled":true}`}, actor); err == nil {
		t.Fatal("经通用设置接口写入计划备份配置应当被拒绝")
	}
}

// 目标选成「应用自己的备份目录」（配置里 dir 为空）时：
//   - 能保存、能执行，且备份要登记进备份列表 —— 那个目录用户从界面上够不着
//     （不是共享文件夹），不登记就等于文件凭空消失，既看不到也删不掉；
//   - 保留份数**不生效**：同名前缀的手动备份也在那儿，一起按份数清理会误删它们；
//   - 状态里不重复列「副本」：那批文件本来就在备份列表里，列两遍只会让人以为存了两份。
func TestBackupPlanOwnDirectoryTarget(t *testing.T) {
	svc, st := newTestEnv(t)
	ctx := context.Background()
	actor := service.Actor{Username: "tester"}
	own := t.TempDir()
	auth := t.TempDir()
	runner := service.NewBackupPlanRunner(st, "test", service.BackupPlanEnv{
		OwnDir: own, AuthorizedDirs: []string{auth},
	}, nil)
	since := time.Date(2026, 9, 18, 0, 0, 0, 0, time.Local)
	plan := service.BackupPlan{Enabled: true, Freq: service.FreqDaily, At: "03:30", Keep: 2, Dir: ""}

	// 启用保存：不该被「不能放在应用自己的数据目录里」挡住（allowOwn 生效）
	if err := runner.SavePlan(ctx, plan, since, actor); err != nil {
		t.Fatalf("显式选择应用自己的备份目录时应当能保存：%v", err)
	}

	// 放两份「手动备份」占位：它们是同名同前缀的文件，保留份数不许碰它们
	for i, name := range []string{"fn-wireguard-backup-20260917-090000.json", "fn-wireguard-backup-20260918-090000.json"} {
		if err := os.WriteFile(filepath.Join(own, name), []byte("manual"), 0o600); err != nil {
			t.Fatal(err)
		}
		_ = i
	}

	base := time.Date(2026, 9, 19, 3, 30, 0, 0, time.Local)
	for i := 0; i < 3; i++ {
		state := runner.RunNow(ctx, plan, base.Add(time.Duration(i)*time.Minute), false, actor)
		if !state.OK {
			t.Fatalf("第 %d 次备份失败：%s", i+1, state.Error)
		}
		if state.Pruned != 0 {
			t.Fatalf("应用自己的备份目录不应清理旧份（会误删手动备份），实际清理了 %d 个", state.Pruned)
		}
	}

	files, err := service.ListBackupPlanFiles(own)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 5 {
		t.Fatalf("3 份计划备份 + 2 份手动备份都应还在，实际 %d 份", len(files))
	}
	// 每一份计划备份都登记进了备份列表（用 Note 区分手动占位那两份没有记录）
	recs, err := svc.ListUserBackups(ctx)
	if err != nil {
		t.Fatal(err)
	}
	planRecs := 0
	for _, r := range recs {
		if r.Note == "计划备份" {
			planRecs++
		}
	}
	if planRecs != 3 {
		t.Fatalf("3 份计划备份都应登记进备份列表，实际 %d 条", planRecs)
	}

	// 状态：解析出的就是应用自己的备份目录，且不重复列副本
	status := runner.Status(ctx, base.Add(time.Hour))
	if status.ResolvedDir != filepath.Clean(own) {
		t.Fatalf("应解析成应用自己的备份目录，实际 %q", status.ResolvedDir)
	}
	info, err := runner.InspectBackupDir(ctx, status.ResolvedDir)
	if err != nil {
		t.Fatal(err)
	}
	if !info.OK || len(info.Files) != 0 {
		t.Fatalf("该目录可用且不应重复列副本，实际 OK=%v Files=%d", info.OK, len(info.Files))
	}
}

// TestBackupPlanRunBackupNowKeepsActor 确认引擎侧那条「立即执行」入口把执行者带下去。
//
// 界面上点一次「立即执行一次」要写审计，而审计得能看出是谁、从哪个 IP 点的：
// 记成匿名的话，事后翻审计会以为这是系统自己跑的一次 —— 而它偏偏是「谁动过手」这类问题
// 的唯一答案。这条入口是给特权代理用的（界面进程没有授权目录的写权限，见 backupplan.go），
// 执行者要跨进程传，最容易被漏掉。
//
// 顺带固定住「手动执行不看日程」：日程关着也要能跑，否则用户想立刻验一下只能先开日程。
func TestBackupPlanRunBackupNowKeepsActor(t *testing.T) {
	_, st := newTestEnv(t)
	ctx := context.Background()
	target := t.TempDir()
	runner := service.NewBackupPlanRunner(st, "0.9.9-test", service.BackupPlanEnv{
		OwnDir:         t.TempDir(),
		AuthorizedDirs: []string{target},
	}, nil)

	// 日程关闭：手动执行与日程无关
	plan := service.BackupPlan{Enabled: false, Freq: service.FreqDaily, At: "03:30", Keep: 3, Dir: target}
	if err := runner.SavePlan(ctx, plan, time.Now(), service.Actor{Username: "tester"}); err != nil {
		t.Fatal(err)
	}

	ok, file, reason := runner.RunBackupNow(ctx, 42, "alice", "10.0.0.9")
	if !ok || file == "" {
		t.Fatalf("手动执行应当成功：ok=%v file=%q reason=%s", ok, file, reason)
	}
	if _, err := os.Stat(filepath.Join(target, file)); err != nil {
		t.Fatalf("写出的备份应当落在目标目录里：%v", err)
	}

	entries, _, err := st.ListAudit(ctx, model.AuditFilter{Username: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		if e.Action == "backup.plan.run" && e.SrcIP == "10.0.0.9" && e.UserID == 42 {
			found = true
		}
	}
	if !found {
		t.Fatal("审计里应当能看到是谁、从哪个 IP 手动执行的这次备份")
	}
}

// TestBackupPlanWriteCopyViaTarget 覆盖「立即备份 → 另存一份」这条由**代理**执行的写入。
//
// 这条路径此前由界面进程自己写，真机上撞了两次：界面进程对用户授权的共享文件夹没有写权限，
// 于是本地那份写好了、另存那一步报一个用户没法处理的权限错误。现在写入统一走代理，
// 这里固定住三件容易被写漏的事：文件名沿用本地那一份（排障时能对上）、
// 同名时换名而不是覆盖、执行者身份进审计（另存也是「有人动过手」）。
func TestBackupPlanWriteCopyViaTarget(t *testing.T) {
	svc, st := newTestEnv(t)
	ctx := context.Background()
	own := t.TempDir()
	target := t.TempDir()
	actor := service.Actor{UserID: 7, Username: "alice", SrcIP: "10.0.0.9"}

	runner := service.NewBackupPlanRunner(st, "0.9.10-test", service.BackupPlanEnv{
		OwnDir:         own,
		AuthorizedDirs: []string{target},
	}, nil)

	rec, err := svc.CreateBackup(ctx, own, "另存测试", actor)
	if err != nil {
		t.Fatal(err)
	}
	used, err := runner.WriteBackupCopy(ctx, target, rec.ID, actor.UserID, actor.Username, actor.SrcIP)
	if err != nil {
		t.Fatalf("另存应当成功：%v", err)
	}
	if used != rec.Filename {
		t.Fatalf("副本应当沿用本地那份的文件名，实际 %q（本地是 %q）", used, rec.Filename)
	}
	if _, err := os.Stat(filepath.Join(target, used)); err != nil {
		t.Fatalf("副本应当落在目标目录里：%v", err)
	}

	// 再来一次：同名不能覆盖，应当换个名字写出第二份
	again, err := runner.WriteBackupCopy(ctx, target, rec.ID, actor.UserID, actor.Username, actor.SrcIP)
	if err != nil {
		t.Fatalf("第二次另存应当成功：%v", err)
	}
	if again == used {
		t.Fatal("同名副本应当换名，而不是覆盖已有的那一份")
	}
	files, err := service.ListBackupPlanFiles(target)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("目标目录里应当有两份副本，实际 %d 份", len(files))
	}

	// 代理侧的审计：另存也要能看出是谁做的
	entries, _, err := st.ListAudit(ctx, model.AuditFilter{Username: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	copied := false
	for _, e := range entries {
		if e.Action == "backup.copy" && e.SrcIP == "10.0.0.9" {
			copied = true
		}
	}
	if !copied {
		t.Fatal("另存应当在审计里留下执行者")
	}

	// 记录不存在时给一句能读懂的话，而不是把它写成一份空文件
	if _, err := runner.WriteBackupCopy(ctx, target, 99999, actor.UserID, actor.Username, actor.SrcIP); err == nil {
		t.Fatal("备份记录不存在时应当报错")
	}
}
