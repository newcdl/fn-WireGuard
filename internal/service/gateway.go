package service

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"fnwg/internal/model"
	"fnwg/internal/store"
)

// 接入飞牛统一网关（NAS 账号免密登录）。
//
// 边界（必须记住）：
//  1. 网关只保证「这个人已登录飞牛」，**不保证他有什么权限** ——
//     权限一律由本应用的本地账号角色决定；
//  2. `X-Trim-*` 头只有在 Unix Socket 通道上才可信，这一点由 api 层把守
//     （TCP 端口上这些头会被剥掉），本层拿到的一定是已确认来源的身份；
//  3. 飞牛 UID 是映射的唯一键。按用户名映射会让一个叫 admin 的飞牛普通用户
//     直接对上本地管理员账号，那是提权漏洞。

// 登录方式取值。
const (
	// LoginModeBoth 两种方式都可用（默认）：网关免密 + 自建账号密码。
	LoginModeBoth = "both"
	// LoginModeGatewayOnly 关闭端口上的账号密码登录，端口只留安全码应急入口。
	LoginModeGatewayOnly = "gateway_only"
	// LoginModePasswordOnly 关闭网关免密登录（入口仍在，但要求账号密码）。
	LoginModePasswordOnly = "password_only"
)

// SettingLoginMode 是登录方式的设置键（同时会被前端读取，故导出）。
const SettingLoginMode = "login_mode"

// GatewayIdentity 是网关注入并被 api 层确认为可信的身份。
type GatewayIdentity struct {
	UID      string
	Username string
	IsAdmin  bool
}

// gatewayLocalUsername 生成网关账号对应的本地用户名。
//
// 带 `nas:` 前缀是刻意的：它必须与用户自建的用户名分属两个命名空间，
// 否则飞牛里一个叫 admin 的普通用户就会撞上本地管理员账号。
func gatewayLocalUsername(uid string) string { return "nas:" + uid }

// externalPasswordHash 是被映射账号的口令散列占位值。
//
// 它不是一个合法的 argon2id 串，VerifyPassword 永远返回 false ——
// 即「这个账号不可能用密码登录」，这正是我们要的：网关账号只能从网关进。
// 不用随机真口令，是因为随机口令仍是一个可被写入、被备份带走的秘密，
// 而一个格式非法的占位值根本没有「正确答案」可言。
const externalPasswordHash = "external:sso"

// LoginMode 返回当前登录方式；未设置时视为 LoginModeBoth。
func (s *Service) LoginMode(ctx context.Context) string {
	v := s.Store.GetSetting(ctx, SettingLoginMode, LoginModeBoth)
	switch v {
	case LoginModeGatewayOnly, LoginModePasswordOnly:
		return v
	default:
		return LoginModeBoth
	}
}

// GatewayEverLoggedIn 表示本实例是否成功用过网关登录。
//
// 判定依据是身份映射表里有没有记录 —— 不额外存时间戳，
// 因为任何「最近一次」之类的设置项都会被写进设置快照的差异里，平白制造噪音。
func (s *Service) GatewayEverLoggedIn(ctx context.Context) bool {
	list, err := s.Store.ListGatewayIdentities(ctx)
	return err == nil && len(list) > 0
}

// SetLoginMode 修改登录方式（运行期）。
//
// 防自锁：启用「仅网关登录」前必须先证明网关真的能进来，否则一旦网关侧异常，
// 用户既进不了界面也改不回来（安全码还能救，但不该把人逼到那一步）。
func (s *Service) SetLoginMode(ctx context.Context, mode string, a Actor) error {
	if err := checkLoginMode(mode, s.GatewayEverLoggedIn(ctx), false); err != nil {
		return err
	}
	return s.writeLoginMode(ctx, mode, a)
}

// SetLoginModeAtSetup 是初始化流程里的登录方式设定。
//
// 与运行期唯一的差别在判据：运行期问的是「历史上成功用过免密登录吗」，
// 初始化时问的是「这一次请求本身是不是经飞牛网关通道带着身份进来的」（见 api 层
// gatewayTrusted）。后者是更强的证明 —— 免密要用到的身份头此刻就在这个请求里，
// 不存在「猜它能不能用」；而初始化之前本应用从没用过免密登录，历史记录必然为空，
// 若沿用运行期的判据，「仅飞牛账号登录」将永远无法在初始化时被选中。
func (s *Service) SetLoginModeAtSetup(ctx context.Context, mode string, gatewayProven bool, a Actor) error {
	if err := checkLoginMode(mode, gatewayProven, true); err != nil {
		return err
	}
	return s.writeLoginMode(ctx, mode, a)
}

// CheckLoginModeAtSetup 只校验取值、不落库，供初始化在**建号之前**先拦一道。
//
// 之所以必须能「先校验再建号」：取值不合法时若已经建好了管理员，用户看到的是
// 初始化失败，重填一遍却只会得到「系统已初始化」—— 账号在、但他不知道密码算不算数，
// 这是最坏的一种失败形态（从业界惯例看，宁可让他重提一次）。
func (s *Service) CheckLoginModeAtSetup(mode string, gatewayProven bool) error {
	return checkLoginMode(mode, gatewayProven, true)
}

// checkLoginMode 是登录方式取值与防自锁的**唯一**判据。
//
// atSetup 只影响措辞：同一个拒绝理由，在初始化与在运行期能做的补救动作并不相同，
// 说错一步就等于给用户一句他做不到的指引（在初始化页让他「先回桌面点一次」，
// 他点的就是眼前这个页面，永远绕不出去）。
func checkLoginMode(mode string, gatewayProven, atSetup bool) error {
	switch mode {
	case LoginModeBoth, LoginModeGatewayOnly, LoginModePasswordOnly:
	default:
		return errors.New("登录方式取值不合法")
	}
	if mode == LoginModeGatewayOnly && !gatewayProven {
		if atSetup {
			return errors.New("本次不是从飞牛桌面打开的应用，无法确认「飞牛账号免密登录」真的能进来，" +
				"因此不能一上来就关闭账号密码登录。请改选「两种都可用」，" +
				"或先从飞牛桌面打开本应用再初始化")
		}
		return errors.New("还没有成功用过飞牛账号免密登录，不能关闭账号密码登录。" +
			"请先回到飞牛桌面用本应用图标打开一次（确认免密登录可用），再回来开启")
	}
	return nil
}

// writeLoginMode 落库并留档。调用前必须已过 checkLoginMode。
func (s *Service) writeLoginMode(ctx context.Context, mode string, a Actor) error {
	// 改动前留快照：登录方式是「改错了可能进不来」的设置，
	// 恰恰是最需要后悔药的一类改动。初始化时也留一份 —— 它同时是这份
	// 「出厂设置」的基线，日后改坏了至少能看出最初是什么样。
	s.snapshotBefore(ctx, "auth.login_mode", settingsNote([]string{"登录方式"}))
	if err := s.Store.SetSetting(ctx, SettingLoginMode, mode); err != nil {
		return err
	}
	s.audit(ctx, a, "auth.login_mode", "settings", "", "", mode, "ok", "")
	return nil
}

// GatewayLogin 用网关身份换取本地会话。
//
// 首次登录自动开户（等价于把飞牛当作身份提供方），之后每次登录都同步一次角色：
// 飞牛那边撤了某人的管理员，本应用必须跟着降权，否则权限只会涨不会落。
func (s *Service) GatewayLogin(ctx context.Context, gw GatewayIdentity, ua, ip string) (*LoginStep, error) {
	uid := strings.TrimSpace(gw.UID)
	if uid == "" {
		return nil, errors.New("未从飞牛网关获取到用户身份")
	}
	// 网关给的是数字 UID；不是数字说明不是网关注入的头（或格式变了），
	// 与其把它当成一个奇怪的用户名存下来，不如直接拒绝。
	if _, err := strconv.ParseInt(uid, 10, 64); err != nil {
		return nil, errors.New("飞牛网关返回的用户标识格式不正确")
	}
	if s.LoginMode(ctx) == LoginModePasswordOnly {
		s.audit(ctx, Actor{Username: "trim:" + uid, SrcIP: ip}, "auth.gateway_login", "user", uid, "", "", "deny", "管理员已关闭免密登录")
		return nil, errors.New("管理员已关闭「飞牛账号免密登录」，请使用账号密码进入")
	}

	u, err := s.gatewayUser(ctx, uid, gw)
	if err != nil {
		s.audit(ctx, Actor{Username: "trim:" + uid, SrcIP: ip}, "auth.gateway_login", "user", uid, "", "", "deny", err.Error())
		return nil, err
	}
	if u.Status != 1 {
		// 本地停用的账号不能靠网关“复活”：停用是本应用管理员的明确决定。
		s.audit(ctx, Actor{UserID: u.ID, Username: u.Username, SrcIP: ip}, "auth.gateway_login", "user", fmt.Sprint(u.ID), "", "", "deny", "账号已被停用")
		return nil, errors.New("该账号已在应用内被停用，请联系应用管理员")
	}
	step, err := s.issueSession(ctx, u, ua, ip)
	if err != nil {
		return nil, err
	}
	// 上面 issueSession 记的是 auth.login；这里补一条说明会话来自网关免密，
	// 便于事后区分「谁走的是哪条入口」。
	s.audit(ctx, Actor{UserID: u.ID, Username: u.Username, SrcIP: ip}, "auth.gateway_login", "user",
		fmt.Sprint(u.ID), "", "飞牛账号 "+gw.Username, "ok", "")
	return step, nil
}

// gatewayUser 取到（必要时创建）网关身份对应的本地账号，并同步角色。
func (s *Service) gatewayUser(ctx context.Context, uid string, gw GatewayIdentity) (*model.User, error) {
	role := gatewayRole(gw.IsAdmin)

	g, err := s.Store.GetGatewayIdentity(ctx, uid)
	switch {
	case err == nil:
		u, err := s.Store.GetUser(ctx, g.UserID)
		if err != nil {
			return nil, errors.New("账号映射已失效，请让应用管理员重新处理")
		}
		if u.Role != role {
			u.Role = role
			if err := s.Store.UpdateUser(ctx, u); err != nil {
				return nil, err
			}
		}
		g.TrimUsername, g.IsAdmin = gw.Username, gw.IsAdmin
		if err := s.Store.UpdateGatewayIdentity(ctx, g); err != nil {
			return nil, err
		}
		return u, nil

	case errors.Is(err, store.ErrNotFound):
		u := &model.User{
			Username:     gatewayLocalUsername(uid),
			PasswordHash: externalPasswordHash,
			Role:         role,
			Status:       1,
		}
		if err := s.Store.CreateUser(ctx, u); err != nil {
			return nil, fmt.Errorf("创建飞牛账号映射失败: %w", err)
		}
		if err := s.Store.CreateGatewayIdentity(ctx, &store.GatewayIdentity{
			TrimUID: uid, UserID: u.ID, TrimUsername: gw.Username, IsAdmin: gw.IsAdmin,
		}); err != nil {
			return nil, fmt.Errorf("记录飞牛账号映射失败: %w", err)
		}
		s.audit(ctx, Actor{Username: "trim:" + uid}, "user.create", "user",
			fmt.Sprint(u.ID), "", u.Username+"/"+role, "ok", "由飞牛账号自动创建")
		return u, nil

	default:
		return nil, err
	}
}

// gatewayRole 是已确认的角色映射：飞牛管理员 → 本应用管理员，其余 → 只读。
func gatewayRole(isAdmin bool) string {
	if isAdmin {
		return model.RoleAdmin
	}
	return model.RoleViewer
}

// GatewayAccountInfo 描述某本地账号是否来自飞牛网关，供界面标注来源。
type GatewayAccountInfo struct {
	TrimUID      string
	TrimUsername string
	IsAdmin      bool
}

// GatewayAccounts 返回「本地账号 ID → 网关来源」的映射，供账号列表标注。
func (s *Service) GatewayAccounts(ctx context.Context) (map[int64]GatewayAccountInfo, error) {
	list, err := s.Store.ListGatewayIdentities(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[int64]GatewayAccountInfo, len(list))
	for _, g := range list {
		out[g.UserID] = GatewayAccountInfo{TrimUID: g.TrimUID, TrimUsername: g.TrimUsername, IsAdmin: g.IsAdmin}
	}
	return out, nil
}

// 账号来源取值，与 model.User.Source 一致。
const (
	// SourceGateway：由飞牛账号映射而来，只能在网关通道上免密进入。
	SourceGateway = "gateway"
	// SourceLocal：应用内自建账号，用账号密码登录。
	SourceLocal = "local"
)

// IsGatewayUser 判断某本地账号是否由飞牛网关映射而来。
//
// 判定依据是映射表里有没有它的记录，而不是「用户名里有没有冒号」：
// 冒号只是生成规则，规则一旦调整，靠字符串猜的地方会集体失效，
// 而映射表是唯一事实来源。映射不存在时返回 false（当作本地账号处理），
// 因此这个函数永远不会把本地账号误判成飞牛账号、进而挡掉它的正常操作。
func (s *Service) IsGatewayUser(ctx context.Context, userID int64) bool {
	g, err := s.Store.GetGatewayIdentityByUser(ctx, userID)
	return err == nil && g != nil
}

// gatewayTOTPRefusal 是「给飞牛账号做本应用二次验证」时的统一拒绝理由。
//
// 这不是「暂时没做」，而是这条路上它**不可能生效**：飞牛账号只能从统一网关
// 免密进入，而网关入口（GatewayLogin）在确认身份后直接签发会话，根本不经过
// 本应用的动态口令校验 —— 飞牛的二次验证由飞牛在网关那一侧自己做。
// 在这里给一个开关，等于给用户一个永远不起作用的假开关，比没有更糟。
const gatewayTOTPRefusal = "飞牛账号的二次验证由飞牛 NAS 统一管理，本应用里无法为它开启：" +
	"它从飞牛桌面免密进入，不经过本应用的动态口令校验。请到飞牛的账号安全设置里开启"

// gatewayPasswordRefusal 是「给飞牛账号设密码」时的统一拒绝理由。
//
// 飞牛账号在本地是一个映射出来的影子账号：口令是映射时写入的占位值，
// 本人登录走网关免密、从不比对它。所以在这里「重置密码」不会有任何效果 ——
// 与其给出一个看起来成功、实际永远用不上的结果，不如直接说清该去哪里改。
const gatewayPasswordRefusal = "这个账号对应飞牛里的账号，密码由飞牛 NAS 统一管理，" +
	"本应用改不了 —— 请到飞牛「用户管理」里修改；想让它在这里也能用密码登录，请改用应用内自建账号"

// decorateUserSource 给账号填上来源与展示名（只作用于返回给界面的那份数据）。
func (s *Service) decorateUserSource(ctx context.Context, u *model.User) {
	if u == nil {
		return
	}
	g, err := s.Store.GetGatewayIdentityByUser(ctx, u.ID)
	if err != nil || g == nil {
		u.Source, u.DisplayName = SourceLocal, u.Username
		return
	}
	u.Source = SourceGateway
	u.TrimUID = g.TrimUID
	u.DisplayName = g.TrimUsername
	if u.DisplayName == "" {
		// 飞牛没给用户名时（早期记录或网关异常）也不能退回 nas:<uid>：
		// 那正是用户看不懂的东西。退回「飞牛账号 <uid>」至少还能让人对上号，
		// 而且 uid 是他在飞牛用户列表里能核对到的。
		u.DisplayName = "飞牛账号 " + g.TrimUID
	}
}
