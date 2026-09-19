// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"fnwg/internal/model"
	"fnwg/internal/store"
	"fnwg/internal/sysutil"
)

// 计划备份：按日程把一份全量备份写到用户授权的共享文件夹。
//
// 为什么值得单独做：界面上点一下就能导出的备份，文件和数据库躺在同一块盘上。
// 盘坏了、目录被误删、系统重装，源和备份一起没——而这正是备份最该防住的几件事。
// 因此目标目录必须落在应用自己的数据目录之外，这一点在保存配置时会被明确拒绝。
//
// 目标目录为什么只能选、不能填：飞牛的应用只能访问**用户授权给它的**目录
// （运行时通过 TRIM_DATA_ACCESSIBLE_PATHS 给到应用）。权限之外的路径一定写不进去，
// 让用户手填一个「看着对」的路径，只会得到「开关是开的、每天失败一次」。
// 授权目录仍在 NAS 上，通常只是另一块存储空间——所以界面上不写「NAS 之外」这种说法。
//
// 为什么做成独立组件而不是 Service 的方法：它要在**代理进程**的定时循环里跑，
// 而那里没有 Service（那边只有引擎与存储）。挂在这里，界面进程（保存配置、手动执行）
// 与代理进程（按日程执行）用的是同一份实现，不会各自长出一套口径。
const (
	// SettingBackupPlan 计划备份的配置（JSON）。
	SettingBackupPlan = "backup_plan"
	// SettingBackupPlanLast 最近一次执行结果（JSON）。
	//
	// 与配置分开存：它是运行时状态、界面只读。混在一起就会出现
	// 「用户保存配置」与「后台记录结果」互相覆盖，而且是静默的。
	SettingBackupPlanLast = "backup_plan_last"
	// SettingBackupPlanSince 计划生效的时间点（unix 秒）。
	//
	// 它解决的是「刚打开开关就立刻补跑一次」：判断该不该执行靠的是
	// 「最近一次执行早于上一个日程点」，而刚启用时最近一次执行是空的——
	// 没有这个基准，用户下午三点打开开关，会立刻收到一份计划外的备份。
	SettingBackupPlanSince = "backup_plan_since"

	// 保留份数的合理区间。
	MinBackupKeep = 1
	MaxBackupKeep = 90
	// DefaultBackupKeep 默认保留份数。按每天一份算是一周余量：
	// 扛得住一次盘满或写坏，也不会失控增长。
	DefaultBackupKeep = 7
	// BackupPlanFilePrefix / BackupPlanFileSuffix 是本应用写进目标目录的文件名规则。
	//
	// 清理**只**认这个前缀：目标目录是用户自己的目录，里面完全可能有别的东西，
	// 只能删自己写下的（与「不接管别人的网卡」同一条原则）。
	BackupPlanFilePrefix = "fn-wireguard-backup-"
	BackupPlanFileSuffix = ".json"

	// FreqDaily / FreqWeekly 执行频率。
	FreqDaily  = "daily"
	FreqWeekly = "weekly"
)

// planMu 串行化执行与清理。
//
// 必须是包级锁而不是执行器实例的字段：同一個进程里，界面（用户点「立即执行」）
// 与定时循环各持有一个执行器实例。两个 goroutine 同时读配置、写文件、清理旧份，
// 会写出两份同名文件，或者把对方刚写下的那份当成「多出来的」删掉。
var planMu sync.Mutex

// BackupPlan 是计划备份的配置。
type BackupPlan struct {
	Enabled bool `json:"enabled"`
	// Freq 频率：daily（每天）或 weekly（每周一次）。
	Freq string `json:"freq"`
	// At 执行时刻，格式 HH:MM（NAS 本地时间）。
	//
	// 用「几点几分」而不是「每隔多少小时」：用户想的是「每天凌晨三点备一次」，
	// 而不是「每 86400 秒一次」——后者会在重启后漂到半夜之外的时间。
	At string `json:"at"`
	// Weekday 每周执行的那一天：1=周一 … 7=周日（仅 weekly 有效）。
	Weekday int `json:"weekday"`
	// Dir 目标目录（绝对路径）。
	Dir string `json:"dir"`
	// Keep 保留份数（含本次写下的那份）。
	Keep int `json:"keep"`
}

// BackupRunState 是最近一次执行的结果。
type BackupRunState struct {
	At time.Time `json:"at"`
	OK bool      `json:"ok"`
	// Manual 表示由用户点「立即执行一次」触发（与按日程区分，界面据此措辞）。
	Manual bool   `json:"manual,omitempty"`
	File   string `json:"file,omitempty"`
	Size   int64  `json:"size,omitempty"`
	// Pruned 本次清理掉的旧份数。
	Pruned int `json:"pruned,omitempty"`
	// Error 失败原因，一句话，直接显示给用户。
	Error string `json:"error,omitempty"`
}

// BackupPlanFile 是目标目录里的一份备份副本。
// BackupPlanFile 是目标目录里的一份副本。
//
// 直接用 model.BackupCopy：它要以同一形状穿过「代理 → 协议 → 界面」三层，
// 各写一份迟早会有一处字段或 json tag 走偏，而那种偏差只表现为「界面少一列」。
type BackupPlanFile = model.BackupCopy

// BackupPlanStatus 是计划备份的完整状态，界面一次取全。
type BackupPlanStatus struct {
	Plan BackupPlan `json:"plan"`
	// Last 最近一次执行结果；从没执行过时为空。
	Last *BackupRunState `json:"last,omitempty"`
	// Since 计划生效时间（上次开启开关的时刻）。
	Since *time.Time `json:"since,omitempty"`
	// NextAt 下次预计执行时间。
	NextAt *time.Time `json:"next_at,omitempty"`
	// Files 目标目录里本应用写下的备份，新的在前。
	Files []BackupPlanFile `json:"files"`
	// DirOK 目标目录当前是否可写；DirNote 是原因。
	DirOK   bool   `json:"dir_ok"`
	DirNote string `json:"dir_note,omitempty"`
	// AuthorizedDirs 是用户在飞牛里授权给本应用的目录，界面据此提供「选择」而不是让用户手填。
	AuthorizedDirs []string `json:"authorized_dirs"`
	// AuthRequired 表示是否必须从上面那份清单里选（开发模式为 false，那时没有飞牛的授权环境变量）。
	AuthRequired bool `json:"auth_required"`
	// ResolvedDir 是配置解析出来的实际落盘目录：配置里为空时就是应用自己的备份目录。
	ResolvedDir string `json:"resolved_dir"`
}

// BackupPlanEnv 是执行计划备份需要的环境事实（都由 cmd 层从飞牛注入的环境变量取）。
type BackupPlanEnv struct {
	// OwnDir 是应用自己的数据目录（备份与快照就落在这里），用于拒绝把目标设在里面。
	OwnDir string
	// AuthorizedDirs 是用户在飞牛里授予本应用访问权限的目录（TRIM_DATA_ACCESSIBLE_PATHS）。
	// 目标目录必须落在其中：授权之外的路径一定写不进去，只是失败得晚一点。
	AuthorizedDirs []string
	// Dev 为开发模式：本地没有飞牛的授权环境变量，因此跳过授权校验（只保留可写探测）。
	Dev bool
	// GroupID 是应用运行用户组的 gid（0 表示未知）。
	//
	// 用途只有一个：把**我们自己**在授权目录里建的子目录归到本应用属组（setgid + 0770），
	// 让界面进程也能读写其中由特权代理写出的备份文件 —— 下载副本、用它还原、另存副本都靠它。
	// 授权目录本身是用户的目录，绝不改动（那条路靠启动脚本补的 ACL）。
	GroupID int
}

// BackupPlanRunner 执行计划备份：读配置、生成备份、写目标目录、清理旧份、记录结果。
type BackupPlanRunner struct {
	st      *store.Store
	version string
	log     *slog.Logger
	env     BackupPlanEnv
}

// NewBackupPlanRunner 创建执行器。
func NewBackupPlanRunner(st *store.Store, version string, env BackupPlanEnv, logger *slog.Logger) *BackupPlanRunner {
	if logger == nil {
		logger = slog.Default()
	}
	return &BackupPlanRunner{st: st, version: version, env: env, log: logger}
}

// DefaultBackupPlan 返回默认配置：关闭、每天 03:30、保留 7 份。
//
// 默认时刻选凌晨三点半：那时设备基本都歇了，备份不会跟正常使用抢磁盘。
func DefaultBackupPlan() BackupPlan {
	return BackupPlan{Freq: FreqDaily, At: "03:30", Weekday: 1, Keep: DefaultBackupKeep}
}

// LoadBackupPlan 读取配置。
//
// 没存过或内容坏了都回落到默认值：坏值时不让整个功能瘫在解析错误上，
// 用户要的是一份能用的配置，而不是一句「配置解析失败」。
func LoadBackupPlan(ctx context.Context, st *store.Store) BackupPlan {
	plan := DefaultBackupPlan()
	raw := strings.TrimSpace(st.GetSetting(ctx, SettingBackupPlan, ""))
	if raw == "" {
		return plan
	}
	if err := json.Unmarshal([]byte(raw), &plan); err != nil {
		return DefaultBackupPlan()
	}
	// 逐项回落到合法取值：文件可能来自旧版本或被手工改过，
	// 一个越界的保留份数会让「清理」变成「删掉刚写的那份」。
	if plan.Keep < MinBackupKeep || plan.Keep > MaxBackupKeep {
		plan.Keep = DefaultBackupKeep
	}
	if plan.Freq != FreqWeekly {
		plan.Freq = FreqDaily
	}
	if _, _, ok := parseClock(plan.At); !ok {
		plan.At = DefaultBackupPlan().At
	}
	if plan.Weekday < 1 || plan.Weekday > 7 {
		plan.Weekday = 1
	}
	return plan
}

// Validate 校验结构字段（与是否启用无关，执行前也要过一遍）。
func (p BackupPlan) Validate() error {
	if p.Freq != FreqDaily && p.Freq != FreqWeekly {
		return fmt.Errorf("执行频率只能是「每天」或「每周」")
	}
	if _, _, ok := parseClock(p.At); !ok {
		return fmt.Errorf("执行时刻要写成 24 小时制的 HH:MM，例如 03:30")
	}
	if p.Freq == FreqWeekly && (p.Weekday < 1 || p.Weekday > 7) {
		return fmt.Errorf("每周执行要指定星期几（1=周一 … 7=周日）")
	}
	if p.Keep < MinBackupKeep || p.Keep > MaxBackupKeep {
		return fmt.Errorf("保留份数需要在 %d 到 %d 之间", MinBackupKeep, MaxBackupKeep)
	}
	return nil
}

// resolvedDir 返回配置对应的实际落盘目录。
//
// 空串不是「没填」，而是「应用自己的备份目录」——界面上第一个选项就是它。
// 好处是这份配置经得起环境变化：不写死路径，应用数据目录换地方（换存储空间、改安装位置）也跟得上。
func (r *BackupPlanRunner) resolvedDir(plan BackupPlan) string {
	if strings.TrimSpace(plan.Dir) == "" {
		return filepath.Clean(r.env.OwnDir)
	}
	return filepath.Clean(strings.TrimSpace(plan.Dir))
}

// isOwnDir 判断目标是不是应用自己的备份目录。
func (r *BackupPlanRunner) isOwnDir(dir string) bool {
	own := strings.TrimSpace(r.env.OwnDir)
	return own != "" && filepath.Clean(dir) == filepath.Clean(own)
}

// CheckTargetPolicy 只看「这个位置允不允许当目标」，不碰文件系统。
//
// 两道结构性约束（理由见 CheckBackupTarget）：
//  1. 落在用户已授权给本应用的目录里；
//  2. 不落在应用自己的数据目录里 —— 否则备份与源数据同盘，盘坏或目录被清会一起丢。
//
// 单独拆出来，是因为「能不能写」必须由**真正执行写入的进程**回答：
// 界面进程（fnwg）对用户授权的共享文件夹往往没有写权限，而写入其实发生在特权代理里。
// 界面这边只该管政策（用户授权了哪些目录、哪些位置不允许），事实交给代理去问。
func CheckTargetPolicy(dir string, env BackupPlanEnv, allowOwn bool) error {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return fmt.Errorf("请选择备份目标目录")
	}
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("目标目录要写绝对路径，例如 /vol1/1000/backup")
	}
	clean := filepath.Clean(dir)

	ownDir := ""
	if v := strings.TrimSpace(env.OwnDir); v != "" {
		ownDir = filepath.Clean(v)
	}
	// 显式选了「应用自己的备份目录」：跳过下面两道结构性检查。
	//
	// 它由 fnOS 依据 config/resource 创建并授予本应用属组权限，**本来就不在
	// 「用户授权目录」清单里**（那份清单说的是用户允许应用碰他的哪些目录），
	// 拿授权清单去否它只会得到一个荒谬的结论：界面上摆着的选项一选就报错。
	if allowOwn && ownDir != "" && clean == ownDir {
		return nil
	}
	switch {
	case len(env.AuthorizedDirs) > 0:
		// 有授权清单就按清单来，无论是不是开发模式：这份清单来自飞牛，
		// 本地把它导出来调试时，就该按真实口径校验。
		if !insideAnyDir(clean, env.AuthorizedDirs) {
			return fmt.Errorf("目标目录不在已授权的目录里：%s（已授权：%s）",
				clean, strings.Join(env.AuthorizedDirs, "、"))
		}
	case !env.Dev:
		return fmt.Errorf("还没有授权目录：请到飞牛的「应用中心 → WireGuard 管理工具 → 应用设置」里，" +
			"把要备份到的共享文件夹授权给本应用，再回到这里选择")
	}
	if ownDir != "" && (clean == ownDir || strings.HasPrefix(clean, ownDir+string(os.PathSeparator))) {
		return fmt.Errorf("目标目录不能放在应用自己的数据目录里（%s）：那样备份和源数据在同一处，盘坏或目录被清时会一起丢", ownDir)
	}
	return nil
}

// CheckBackupTarget 校验目标目录可用：政策 + 真的写一次探针。
//
// allowOwn 表示「应用自己的备份目录」这次是合法选择（用户在界面上显式选了它）：
// 那与本机备份同盘，防不住盘坏，但有人就是想让它留在本机（例如只想留几份轮换的本地副本），
// 界面会把代价写清楚。
//
// 调用它的人**必须就是执行写入的那个进程**（特权代理，见 InspectBackupDir）：
// 拿别的身份的权限去问「能不能写」，答案与实际执行无关，只会产出
// 「目录明明在授权列表里、界面却说不可写」这种自相矛盾的提示（真机上出现过两次）。
func CheckBackupTarget(dir string, env BackupPlanEnv, allowOwn bool) error {
	if err := CheckTargetPolicy(dir, env, allowOwn); err != nil {
		return err
	}
	clean := filepath.Clean(strings.TrimSpace(dir))
	// 子目录允许不存在：界面里选的是「授权目录 + 子目录名」，用户不必先去文件管理里手工建文件夹。
	// 建得出来本身就是一道权限证明；建不出来（授权是只读、盘已摘除）会在这里就报清楚。
	switch info, err := os.Stat(clean); {
	case err == nil && !info.IsDir():
		return fmt.Errorf("目标目录不是文件夹：%s", clean)
	case err != nil && !os.IsNotExist(err):
		return fmt.Errorf("打不开目标目录：%v", err)
	case os.IsNotExist(err):
		if err := os.MkdirAll(clean, 0o770); err != nil {
			return fmt.Errorf("目标目录不存在，且无法创建：%v", err)
		}
	}
	// 探针：写一个临时文件再删掉。这是唯一能同时覆盖「权限」与「挂载是否真的可写」的办法。
	probe := filepath.Join(clean, ".fnwg-write-probe")
	if err := os.WriteFile(probe, []byte("probe"), 0o600); err != nil {
		return fmt.Errorf("目标目录不可写：%v", err)
	}
	_ = os.Remove(probe)
	return nil
}

// insideAnyDir 判断路径是否落在给定目录之一里（含其子目录）。
func insideAnyDir(path string, dirs []string) bool {
	for _, d := range dirs {
		d = filepath.Clean(d)
		if path == d || strings.HasPrefix(path, d+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

// parseClock 解析 HH:MM，返回时、分与是否合法。
func parseClock(v string) (int, int, bool) {
	parts := strings.Split(strings.TrimSpace(v), ":")
	if len(parts) != 2 {
		return 0, 0, false
	}
	h, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	m, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err1 != nil || err2 != nil || h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, 0, false
	}
	return h, m, true
}

// Due 判断此刻是否应当执行。
//
// 判据只有两条：① 上一个日程点在「计划生效」之后；② 最近一次执行早于那个日程点。
// 这样不必为「NAS 关机错过时间」「改过时间」额外维护状态：开机后一旦发现上一场日程
// 还没做过，就补一次（少一份备份比晚一点更值得避免）。而刚打开开关那次不算错过
// （基准见 SettingBackupPlanSince），否则用户会被立刻多备一份。
func (p BackupPlan) Due(now, lastAt, since time.Time) bool {
	if !p.Enabled {
		return false
	}
	due, ok := p.lastDue(now)
	if !ok {
		return false
	}
	if !since.IsZero() && !due.After(since) {
		return false
	}
	return lastAt.IsZero() || lastAt.Before(due)
}

// lastDue 返回「不晚于 now 的最近一个日程点」。
func (p BackupPlan) lastDue(now time.Time) (time.Time, bool) {
	h, m, ok := parseClock(p.At)
	if !ok {
		return time.Time{}, false
	}
	cand := time.Date(now.Year(), now.Month(), now.Day(), h, m, 0, 0, now.Location())
	if p.Freq == FreqWeekly {
		// 1=周一 → time.Monday；7=周日 → 7%7=0 → time.Sunday。
		wd := time.Weekday(p.Weekday % 7)
		back := (int(now.Weekday()) - int(wd) + 7) % 7
		cand = cand.AddDate(0, 0, -back)
		if cand.After(now) {
			cand = cand.AddDate(0, 0, -7)
		}
		return cand, true
	}
	if cand.After(now) {
		cand = cand.AddDate(0, 0, -1)
	}
	return cand, true
}

// NextDue 返回下一次执行时间，供界面显示「下一次：明天 03:30」。
//
// 注意它只回答「日程上的下一个点」，不代表「此刻不会补跑」：
// 若已经错过了上一场日程，下一次检查（最多 5 分钟后）就会立刻执行。
func (p BackupPlan) NextDue(now time.Time) (time.Time, bool) {
	if !p.Enabled {
		return time.Time{}, false
	}
	h, m, ok := parseClock(p.At)
	if !ok {
		return time.Time{}, false
	}
	cand := time.Date(now.Year(), now.Month(), now.Day(), h, m, 0, 0, now.Location())
	switch p.Freq {
	case FreqWeekly:
		wd := time.Weekday(p.Weekday % 7)
		ahead := (int(wd) - int(now.Weekday()) + 7) % 7
		cand = cand.AddDate(0, 0, ahead)
		if !cand.After(now) {
			cand = cand.AddDate(0, 0, 7)
		}
	default:
		if !cand.After(now) {
			cand = cand.AddDate(0, 0, 1)
		}
	}
	return cand, true
}

// Describe 用一句话描述配置，供审计与日志使用。
func (p BackupPlan) Describe() string {
	if !p.Enabled {
		return "已关闭"
	}
	when := "每天 " + p.At
	if p.Freq == FreqWeekly {
		when = "每周" + weekdayLabel(p.Weekday) + " " + p.At
	}
	dir := strings.TrimSpace(p.Dir)
	if dir == "" {
		// 与界面上的说法保持一致，审计里也一眼能看懂
		dir = "应用自己的备份目录"
	}
	return fmt.Sprintf("%s · 保留 %d 份 · 目标 %s", when, p.Keep, dir)
}

// weekdayLabel 把 1..7 转成中文星期。
func weekdayLabel(n int) string {
	labels := [...]string{"", "一", "二", "三", "四", "五", "六", "日"}
	if n < 1 || n > 7 {
		return ""
	}
	return labels[n]
}

// Status 汇总计划备份的当前状态。
func (r *BackupPlanRunner) Status(ctx context.Context, now time.Time) *BackupPlanStatus {
	plan := LoadBackupPlan(ctx, r.st)
	out := &BackupPlanStatus{
		Plan:           plan,
		Last:           loadBackupRunState(ctx, r.st),
		Files:          []BackupPlanFile{},
		AuthorizedDirs: r.env.AuthorizedDirs,
		// 有授权清单时必须从清单里选（见 ValidateBackupTarget 的同一条判断）；
		// 生产环境即使清单为空也算「必须」，好在界面上直接说明去哪儿授权。
		AuthRequired: len(r.env.AuthorizedDirs) > 0 || !r.env.Dev,
	}
	if out.AuthorizedDirs == nil {
		out.AuthorizedDirs = []string{}
	}
	if since := loadBackupPlanSince(ctx, r.st); !since.IsZero() {
		out.Since = &since
	}
	// NextAt 只在启用时才有意义：关闭时显示一个「下次执行时间」会让人以为它还会跑。
	if plan.Enabled {
		if next, ok := plan.NextDue(now); ok {
			out.NextAt = &next
		}
	}
	// 空串不是「没填」，而是「应用自己的备份目录」（界面第一个选项）。这里把它解析出来，
	// 界面据此显示实际会写到哪，不必自己拼路径。
	out.ResolvedDir = r.resolvedDir(plan)
	if r.isOwnDir(out.ResolvedDir) && strings.TrimSpace(r.env.OwnDir) == "" {
		// 连自己的数据目录都不知道（命令行/测试环境），别假装算得出来
		out.DirNote = "还没设置目标目录"
	}
	// 这里刻意不判断「目标目录能不能写、里面有哪些副本」：那是**事实**，
	// 只有真正执行写入的进程（特权代理）答得准。界面进程去问，问出来的是它自己的权限，
	// 与备份能否成功无关 —— 接口层会向代理取这个结论再合并进来（见 handleBackupPlanStatus）。
	return out
}

// rejectPlanSettings 拒绝经通用设置接口写入计划备份的配置。
//
// 它是一组互相约束的字段（日程 + 目标目录 + 保留份数）：逐键写入既无法整体校验，
// 也会绕过目标目录的可写探测——那正是「开关看着是开的、其实每天失败」的来源。
// 因此这里直接拒绝，只留 PUT /backup-plan 一条写入路径。
func rejectPlanSettings(kv map[string]string) error {
	for k := range kv {
		if strings.HasPrefix(k, "backup_plan") {
			return fmt.Errorf("计划备份的配置请通过备份页保存（收到的是 %s）", k)
		}
	}
	return nil
}

// SavePlan 保存配置。
//
// 启用时必须先确认目标目录真的能写：否则这个开关是「假打开」的——
// 界面显示着「已开启 · 每天 03:30」，实际每天失败一次，而用户以为有备份。
// 备份这类功能最怕的不是报错，而是安静地不工作。
func (r *BackupPlanRunner) SavePlan(ctx context.Context, plan BackupPlan, now time.Time, a Actor) error {
	if err := plan.Validate(); err != nil {
		return err
	}
	old := LoadBackupPlan(ctx, r.st)
	// 只在「要打开这个开关」或「换了目标目录」时探测目录，其余情况放行。
	//
	// 已经启用、只是改个时间，却被「磁盘此刻不在」挡住保存，是帮倒忙：
	// 挡下来并不能改变「它本来就是坏的」，只会让人改不了配置。
	// 而目录真的坏了这件事，状态区会显示、执行失败也会推送，不会被悄悄放过。
	if plan.Enabled && (!old.Enabled || plan.Dir != old.Dir) {
		// 只校验政策（位置允不允许）。可写与否由代理判定：接口层在保存后向代理要一次结论，
		// 拿到「写不进去」就回 400 —— 界面进程自己探测会把「它没权限」误报成「目标不可用」。
		if err := CheckTargetPolicy(r.resolvedDir(plan), r.env, r.isOwnDir(r.resolvedDir(plan))); err != nil {
			return err
		}
	}
	raw, err := json.Marshal(plan)
	if err != nil {
		return err
	}
	if err := r.st.SetSetting(ctx, SettingBackupPlan, string(raw)); err != nil {
		return err
	}
	// 从「关闭」变为「启用」时记下生效时间，作为「有没有错过日程」的起点。
	if plan.Enabled && !old.Enabled {
		if err := r.st.SetSetting(ctx, SettingBackupPlanSince, strconv.FormatInt(now.Unix(), 10)); err != nil {
			return err
		}
	}
	r.audit(ctx, a, "backup.plan.save", plan.Dir, "ok", "计划备份："+plan.Describe())
	return nil
}

// RunIfDue 到点则执行一次，供定时循环调用。
//
// 返回「是否执行、是否成功、失败原因」三个原始值而不是结构体：
// 调用方是收敛引擎，它不该为了收一个结果去依赖本包的类型。
func (r *BackupPlanRunner) RunIfDue(ctx context.Context, now time.Time) (ran, ok bool, reason string) {
	plan := LoadBackupPlan(ctx, r.st)
	if !plan.Enabled {
		return false, false, ""
	}
	var lastAt time.Time
	if last := loadBackupRunState(ctx, r.st); last != nil {
		lastAt = last.At
	}
	if !plan.Due(now, lastAt, loadBackupPlanSince(ctx, r.st)) {
		return false, false, ""
	}
	state := r.RunNow(ctx, plan, now, false, Actor{Username: "system"})
	return true, state.OK, state.Error
}

// RunBackupNow 实现 reconcile.BackupPlanRunner：立刻执行一次。
//
// 与 RunNow 的差别只在调用方：RunNow 由界面接口直接调用（返回完整状态好序列化给前端），
// 这个给引擎用 —— 引擎的接口只认原始值，见 reconcile.BackupPlanRunner 的说明。
func (r *BackupPlanRunner) RunBackupNow(ctx context.Context, userID int64, username, srcIP string) (bool, string, string) {
	plan := LoadBackupPlan(ctx, r.st)
	a := Actor{UserID: userID, Username: username, SrcIP: srcIP}
	if a.Username == "" {
		a.Username = "system"
	}
	state := r.RunNow(ctx, plan, time.Now(), true, a)
	return state.OK, state.File, state.Error
}

// RunNow 立即执行一次，并把结果写进状态、审计与日志。
//
// 失败不返回 error：调用方（界面按钮、定时循环）需要的信息是「为什么失败」，
// 而它同时要落到状态里给用户看。把原因放进返回值，比让调用方事后再查一遍更不容易漏。
func (r *BackupPlanRunner) RunNow(ctx context.Context, plan BackupPlan, now time.Time, manual bool, a Actor) *BackupRunState {
	planMu.Lock()
	defer planMu.Unlock()

	state := &BackupRunState{At: now, Manual: manual}
	fail := func(format string, args ...any) *BackupRunState {
		state.OK, state.Error = false, fmt.Sprintf(format, args...)
		r.saveRunState(ctx, state)
		r.log.Warn("计划备份失败", "dir", plan.Dir, "err", state.Error)
		_ = r.st.AddLog(ctx, "warn", "backup", "计划备份失败", state.Error)
		r.audit(ctx, a, "backup.plan.run", plan.Dir, "fail", state.Error)
		return state
	}

	if err := plan.Validate(); err != nil {
		return fail("%s", err.Error())
	}
	// 空串就是「应用自己的备份目录」，落到实际路径再校验。
	target := r.resolvedDir(plan)
	ownTarget := r.isOwnDir(target)
	if err := CheckBackupTarget(target, r.env, ownTarget); err != nil {
		return fail("%s", err.Error())
	}
	// 目标是我们自己在授权目录里建的下层目录时，把它归到本应用属组（setgid + 0770）：
	// 按日程那份由 root 写出，界面进程要能读它（下载副本、用它还原）、也要能写它（另存副本）。
	// 授权目录本身是用户的目录，一个字节都不碰 —— 那条路靠启动脚本补的 ACL。
	if r.env.GroupID > 0 && !equalsAnyDir(target, r.env.AuthorizedDirs) {
		sysutil.FixGroup(target, r.env.GroupID, 0o2770)
	}
	payload, err := BuildBackupPayload(ctx, r.st, r.version, true)
	if err != nil {
		return fail("生成备份内容失败：%v", err)
	}
	raw, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fail("整理备份内容失败：%v", err)
	}

	// 先占到名字（O_EXCL），再写临时文件改名过去。
	// 占名是为了挡住「同一秒里的另一次写入」：定时执行在代理进程、手动另存在 web 进程，
	// 两个进程之间没有共享的锁，只有内核的原子创建能保证不会各写各的同一个名字。
	name, err := reserveBackupName(target, BackupPlanFilePrefix+now.Format("20060102-150405")+BackupPlanFileSuffix, r.fileMode())
	if err != nil {
		return fail("写入目标目录失败：%v", err)
	}
	path := filepath.Join(target, name)
	// 先写临时文件再改名：中途断电、磁盘满时不会在目标目录里留下一个
	// 名字像备份、内容却是半截的文件——那比没有备份更危险，因为它看起来是好的。
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, r.fileMode()); err != nil {
		_ = os.Remove(path) // 释放占位，别留下一个空文件冒充备份
		return fail("写入目标目录失败：%v", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		_ = os.Remove(path)
		return fail("保存备份文件失败：%v", err)
	}

	state.OK, state.File, state.Size = true, name, int64(len(raw))
	if ownTarget {
		// 目标落在应用自己的备份目录时，登记成一条普通备份记录，且**不做保留清理**。
		// 两条各有理由，缺一都会出事：
		//   ① 那个目录用户从界面上够不着（不是共享文件夹），不登记就等于文件凭空消失、
		//      既看不到也删不掉；
		//   ② 文件名与手动备份完全一样，分不出谁是谁，一起按份数清理会误删用户手动做的备份。
		//      要清理就在备份列表里删——那里每一条都看得见。
		sum := sha256.Sum256(raw)
		rec := &store.BackupRecord{
			Filename:   name,
			Size:       int64(len(raw)),
			SHA256:     hex.EncodeToString(sum[:]),
			Kind:       store.BackupKindManual,
			Note:       "计划备份",
			IncludeKey: true,
		}
		if err := r.st.CreateBackupRecord(ctx, rec); err != nil {
			r.log.Warn("登记计划备份记录失败", "err", err)
			_ = r.st.AddLog(ctx, "warn", "backup", "计划备份已写出但未能登记到列表", err.Error())
		}
	} else {
		pruned, perr := r.prune(target, plan.Keep)
		state.Pruned = pruned
		if perr != nil {
			// 清理失败不影响「这次备份成功」：新的一份已经稳稳落盘了。
			// 但要说出来——否则目标目录会一直涨，而用户以为保留策略在生效。
			r.log.Warn("清理旧备份失败", "dir", target, "err", perr)
			_ = r.st.AddLog(ctx, "warn", "backup", "清理旧备份失败", perr.Error())
		}
	}
	r.saveRunState(ctx, state)

	msg := fmt.Sprintf("已写入 %s（%s）", name, humanSize(int64(len(raw))))
	switch {
	case ownTarget:
		msg += "，已登记到备份列表（应用自己的备份目录不做份数清理，请在列表里管理）"
	case state.Pruned > 0:
		msg += fmt.Sprintf("，清理旧份 %d 个", state.Pruned)
	}
	_ = r.st.AddLog(ctx, "info", "backup", "计划备份完成", msg)
	r.audit(ctx, a, "backup.plan.run", name, "ok", msg)
	r.log.Info("计划备份完成", "file", name, "size", len(raw), "pruned", state.Pruned)
	return state
}

// prune 清理超出保留份数的旧备份。
//
// 两个边界：只删本应用写下的文件（目标目录是用户的目录，里面有别的东西很正常）；
// 并且始终保留最新的 Keep 份——按修改时间而不是文件名排序：
// 用户可能把外部拷来的备份也放进来，文件名上的时间戳与落盘先后未必一致。
func (r *BackupPlanRunner) prune(dir string, keep int) (int, error) {
	files, err := ListBackupPlanFiles(dir)
	if err != nil {
		return 0, err
	}
	if len(files) <= keep {
		return 0, nil
	}
	pruned := 0
	for _, f := range files[keep:] {
		if err := os.Remove(filepath.Join(dir, f.Name)); err != nil {
			return pruned, err
		}
		pruned++
	}
	return pruned, nil
}

// ListBackupPlanFiles 列出目标目录里本应用写下的备份，新的在前。
func ListBackupPlanFiles(dir string) ([]BackupPlanFile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := make([]BackupPlanFile, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, BackupPlanFilePrefix) || !strings.HasSuffix(name, BackupPlanFileSuffix) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, BackupPlanFile{Name: name, Size: info.Size(), ModTime: info.ModTime()})
	}
	// 按修改时间倒序，同一时刻再按文件名倒序。
	//
	// 第二重排序不是多余的：连续几次备份可能落在同一秒（手动触发紧接着定时触发），
	// 修改时间完全相等时顺序不确定，而清理正是按这个顺序决定删哪几份——
	// 一旦把「刚写下的那份」排到后面，它就会被当成多余的那份删掉。
	// 文件名里带着时间戳，按名字倒序与按时间倒序是一致的。
	sort.Slice(out, func(i, j int) bool {
		if !out[i].ModTime.Equal(out[j].ModTime) {
			return out[i].ModTime.After(out[j].ModTime)
		}
		return out[i].Name > out[j].Name
	})
	return out, nil
}

// fileMode 返回写出备份文件时用的权限。
//
// 代理（root）写出、界面进程（fnwg）可能要读（下载副本、用它还原）时给属组可读；
// 不涉及跨身份读取时就用最紧的 0600。
func (r *BackupPlanRunner) fileMode() fs.FileMode {
	if r.env.GroupID > 0 {
		return 0o640
	}
	return 0o600
}

// equalsAnyDir 判断路径是否与给定目录之一完全相同（注意：不比子目录）。
func equalsAnyDir(path string, dirs []string) bool {
	path = filepath.Clean(path)
	for _, d := range dirs {
		if filepath.Clean(d) == path {
			return true
		}
	}
	return false
}

// reserveBackupName 在 dir 里占住一个不重名的文件名（O_EXCL 建出空文件），返回实际名字。
//
// 为什么需要：文件名精确到秒，「同一秒内连点两次立即备份」就会撞名。老做法是直接覆盖，
// 结果是数据库里两条记录指向同一个文件 —— 较早那次的内容没了，记录的校验值也与文件对不上。
// 撞名时追加 -2、-3……，并把这个判断交给内核的原子创建，而不是「先查再写」（那中间有窗口）。
func reserveBackupName(dir, name string, mode fs.FileMode) (string, error) {
	ext := filepath.Ext(name)
	base := strings.TrimSuffix(name, ext)
	for i := 1; i <= 50; i++ {
		cand := name
		if i > 1 {
			cand = fmt.Sprintf("%s-%d%s", base, i, ext)
		}
		f, err := os.OpenFile(filepath.Join(dir, cand), os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if err == nil {
			_ = f.Close()
			return cand, nil
		}
		if !os.IsExist(err) {
			return "", err
		}
	}
	return "", fmt.Errorf("同一秒内已存在过多同名备份，请稍后重试")
}

// writeBackupFile 把备份写进 dir 并返回实际使用的文件名（撞名时自动换一个）。
func writeBackupFile(dir, name string, raw []byte, mode fs.FileMode) (string, error) {
	used, err := reserveBackupName(dir, name, mode)
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, used)
	if err := os.WriteFile(path, raw, mode); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	return used, nil
}

// ResolveTarget 返回这份配置实际会写到的目录（空 Dir 解析成应用自己的备份目录）。
//
// 导出给接口层：保存前要让代理按**实际路径**确认目标可用，而路径解析规则（空串 = 应用自己的目录）
// 只应该有一处实现，接口层自己拼一遍迟早会与这里不一致。
func (r *BackupPlanRunner) ResolveTarget(plan BackupPlan) string { return r.resolvedDir(plan) }

// WriteBackupCopy 把一份本地备份另存到用户指定的授权目录。
//
// 由**代理**执行（见 internal/core 与 cmd/fnwg-agent）：写入发生在授权目录上，
// 而界面进程（fnwg）对用户授权的共享文件夹没有写权限。真机上正是这里翻的车 ——
// 「立即备份」里的另存会一路成功到写文件那一步，然后报一个用户没法处理的权限错误。
//
// 源文件按备份 ID 取，而不是让调用方传路径：代理是特权进程，不能接受任意路径
// （协议层刻意不支持任意命令与任意路径，见 internal/agentapi 的说明）。
func (r *BackupPlanRunner) WriteBackupCopy(ctx context.Context, dir string, backupID int64, userID int64, username, srcIP string) (string, error) {
	own := strings.TrimSpace(r.env.OwnDir)
	if own == "" {
		return "", fmt.Errorf("应用自己的备份目录未知，无法读取这份备份")
	}
	recs, err := r.st.ListBackups(ctx)
	if err != nil {
		return "", err
	}
	name := ""
	for i := range recs {
		if recs[i].ID == backupID {
			name = filepath.Base(recs[i].Filename)
		}
	}
	if name == "" {
		return "", fmt.Errorf("备份记录不存在或已被删除")
	}
	raw, err := os.ReadFile(filepath.Join(own, name))
	if err != nil {
		return "", fmt.Errorf("读取备份文件失败：%v", err)
	}

	// allowOwn=false：另存的意义就是「放到别处」，指到应用自己的备份目录等于原地复制一份，
	// 直接拒绝比默默写一份更清楚。
	if err := CheckBackupTarget(dir, r.env, false); err != nil {
		return "", err
	}
	clean := filepath.Clean(strings.TrimSpace(dir))

	planMu.Lock()
	defer planMu.Unlock()
	// 文件名沿用本地那一份：两处能对上，排障时不必猜哪份是哪份。
	// 名字可能已经被占（同名副本已在那儿，或同一秒里被定时任务先写了）：
	// 交给 reserveBackupName 换一个，而不是覆盖别人那份。
	used, err := reserveBackupName(clean, name, r.fileMode())
	if err != nil {
		return "", fmt.Errorf("写入 %s 失败：%v", clean, err)
	}
	path := filepath.Join(clean, used)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, r.fileMode()); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("写入 %s 失败：%v", clean, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		_ = os.Remove(path)
		return "", fmt.Errorf("保存到 %s 失败：%v", clean, err)
	}
	a := Actor{UserID: userID, Username: username, SrcIP: srcIP}
	if a.Username == "" {
		a.Username = "system"
	}
	_ = r.st.AddLog(ctx, "info", "backup", "备份已另存一份", used+" → "+clean)
	r.audit(ctx, a, "backup.copy", used, "ok", "另存到 "+clean)
	return used, nil
}

// ReadBackupCopy 读取目标目录里的一份副本（供界面下载、或用它还原）。
func (r *BackupPlanRunner) ReadBackupCopy(ctx context.Context, dir, name string) ([]byte, error) {
	return ReadBackupPlanFile(dir, name)
}

// InspectBackupDir 检查目标目录并列出其中的副本。
//
// 这是**执行写入的那个进程**（代理）给出的结论，因此可以当成事实用：
// 能写就是能写，不能写就是不能写，不存在「界面说不可写、代理却写得好好的」。
func (r *BackupPlanRunner) InspectBackupDir(ctx context.Context, dir string) (model.BackupDirInfo, error) {
	out := model.BackupDirInfo{Files: []model.BackupCopy{}}
	ownTarget := r.isOwnDir(dir)
	if ownTarget && strings.TrimSpace(r.env.OwnDir) == "" {
		out.Note = "还没设置目标目录"
		return out, nil
	}
	if err := CheckBackupTarget(dir, r.env, ownTarget); err != nil {
		out.Note = err.Error()
		// 写不进去与「里面原来的副本还在不在」是两件事，而此刻用户最想知道的往往正是后者：
		// 仍然尽力列一下，列不出来就只报前面的原因。
		if !ownTarget {
			if files, ferr := ListBackupPlanFiles(dir); ferr == nil {
				out.Files = files
			}
		}
		return out, nil
	}
	out.OK = true
	if ownTarget {
		// 目标就是应用自己的备份目录：不列「副本」——那批文件本来就在上方的备份列表里，
		// 同一批东西列两遍，只会让人以为存了两份。
		return out, nil
	}
	files, err := ListBackupPlanFiles(dir)
	if err != nil {
		out.Note = "读取副本列表失败：" + err.Error()
		return out, nil
	}
	out.Files = files
	return out, nil
}

// ReadBackupPlanFile 读取目标目录里的一份副本（供下载与「用这份还原」使用）。
//
// 只接受「纯文件名 + 本应用的命名前缀」：界面传来的名字不可信，
// 带上路径成分就能读到目标目录之外的任意文件。与备份导入那里是同一道防线。
func ReadBackupPlanFile(dir, name string) ([]byte, error) {
	clean := strings.TrimSpace(name)
	if clean == "" || filepath.Base(clean) != clean ||
		!strings.HasPrefix(clean, BackupPlanFilePrefix) || !strings.HasSuffix(clean, BackupPlanFileSuffix) {
		return nil, fmt.Errorf("文件名不合法")
	}
	path := filepath.Join(dir, clean)
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("文件不存在或已被删除：%s", clean)
	}
	return os.ReadFile(path)
}

// saveRunState 记录最近一次执行结果。
func (r *BackupPlanRunner) saveRunState(ctx context.Context, s *BackupRunState) {
	raw, err := json.Marshal(s)
	if err != nil {
		return
	}
	if err := r.st.SetSetting(ctx, SettingBackupPlanLast, string(raw)); err != nil {
		r.log.Warn("记录计划备份结果失败", "err", err)
	}
}

// audit 写一条审计。动作名统一以 backup.plan 开头，便于在审计页按对象筛选。
func (r *BackupPlanRunner) audit(ctx context.Context, a Actor, action, targetID, result, msg string) {
	if err := r.st.AddAudit(ctx, &model.AuditEntry{
		UserID:     a.UserID,
		Username:   a.Username,
		SrcIP:      a.SrcIP,
		Action:     action,
		TargetType: "backup",
		TargetID:   targetID,
		Result:     result,
		Message:    msg,
	}); err != nil {
		r.log.Warn("写入审计失败", "err", err)
	}
}

// loadBackupRunState 读取最近一次执行结果；没记录过返回 nil。
func loadBackupRunState(ctx context.Context, st *store.Store) *BackupRunState {
	raw := strings.TrimSpace(st.GetSetting(ctx, SettingBackupPlanLast, ""))
	if raw == "" {
		return nil
	}
	var s BackupRunState
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		return nil
	}
	return &s
}

// loadBackupPlanSince 读取计划生效时间。
func loadBackupPlanSince(ctx context.Context, st *store.Store) time.Time {
	n, err := strconv.ParseInt(strings.TrimSpace(st.GetSetting(ctx, SettingBackupPlanSince, "")), 10, 64)
	if err != nil || n <= 0 {
		return time.Time{}
	}
	return time.Unix(n, 0)
}

// humanSize 把字节数写成便于阅读的形式（日志与审计里用）。
func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	units := []string{"KB", "MB", "GB"}
	v := float64(n)
	i := -1
	for v >= unit && i < len(units)-1 {
		v /= unit
		i++
	}
	return fmt.Sprintf("%.1f %s", v, units[i])
}
