# fn-WireGuard

<div align="center">

**飞牛 NAS 原生 WireGuard 可视化管理工具**

[![version](https://img.shields.io/github/v/release/newcdl/fn-WireGuard?label=version&color=blue)](https://github.com/newcdl/fn-WireGuard/releases)
[![license](https://img.shields.io/badge/license-MIT-green)](#license)
[![platform](https://img.shields.io/badge/platform-fnOS-blue)](https://www.fnnas.com)

不需要记任何命令，在界面上点几下，就能让手机、电脑在外网安全地连回家，或把两处网络连成一张网。

</div>

---

## 目录

- [它能做什么](#它能做什么)
- [为什么安全](#为什么安全)
- [快速开始](#快速开始)
- [界面与功能](#界面与功能)
- [命令行工具](#命令行工具)
- [数据与隐私](#数据与隐私)
- [常见问题](#常见问题)
- [构建与开发](#构建与开发)
- [版本规划](#版本规划)
- [参与贡献](#参与贡献)
- [许可证](#license)

---

## 它能做什么

| 场景 | 说明 |
|---|---|
| 在外安全回家 | 手机/电脑在外使用公共 WiFi 时，加密连回 NAS，访问家中所有设备，上网流量走家里线路 |
| 只访问内网 | 只让设备访问家里内网，上网仍走本地网络，速度不受影响 |
| 异地组网 | 把两台 NAS 或两处办公地点的内网打通，像在同一局域网里一样互相访问 |
| 多连接隔离 | 家人、访客、不同用途各建一条连接，互不干扰 |

核心特性：

- **三步上手**：一键创建连接 → 添加设备生成二维码 → 手机扫码即连。
- **多连接互不干扰**：地址与端口按连接序号自动错开（`wg0 → 10.10.0.1/24 + 51820`，`wg1 → 10.11.0.1/24 + 51821`），手工填写时创建前即校验冲突。
- **设备访问家里内网**：连接级开关，由 NAS 对隧道网段做源地址改写，设备连上后能访问 NAS 所在局域网里的其它机器。
- **全程可视化**：连接/设备/密钥/二维码/实时流量/运行记录，全字段白话说明，移动端适配。
- **内置体检**：系统状态、内网访问逐层诊断、疑似残留网卡清理，异常直接告诉你「卡在哪一层、怎么处理」。

## 为什么安全

本应用运行在你的 NAS 上，最忌讳的是「为了组网把系统网络搞挂」。因此它从设计上就守一条铁规则：

> **绝不修改 NAS 系统的网络设置，只操作自己创建的对象，且全部可清理。**

具体保障：

| # | 承诺 | 实现方式 |
|---|---|---|
| 1 | 不接管、不删除别人的网卡 | 状态文件记录「哪些网卡是本应用创建的」，同名异主一律拒绝接管 |
| 2 | 不改系统主路由表 | 需要下发路由时写入专用策略路由表 `51888` + `ip rule`，`ip route show` 与安装前逐字符一致 |
| 3 | 默认不管理本机路由 | 「异地组网」开关默认关闭；即便开启也只对目标网段生效 |
| 4 | 内网访问规则与系统隔离 | 写在应用自己的 nftables 表 `inet fn-wireguard`，只匹配隧道网段，关闭/卸载整表删除 |
| 5 | 密钥加密落盘 | 私钥与口令用 AES-256-GCM 加密，主密钥只存本机并限定属组可读 |
| 6 | 卸载不留痕迹 | 停用/卸载时撤销全部自己创建的路由、规则、网卡 |

> 更详细的实现说明见 [`internal/wgback/`](internal/wgback/)，核心防线都带有穷举式单元测试。

## 快速开始

### 安装

1. 在 [Releases](https://github.com/newcdl/fn-WireGuard/releases) 下载对应架构的安装包；
2. 在 NAS 上执行 `uname -m`：`x86_64` 用 **amd64**，`aarch64` 用 **arm64**；
3. 飞牛 **应用中心 → 手动上传应用**，选择安装包安装。

### 三步连回家

1. **总览 → 一键创建推荐连接**（名称、地址、端口都自动分配）；
2. **我的设备 → 新增设备**，得到二维码；
3. 手机安装 WireGuard 官方 App，**扫一扫**即可。

> 在外网使用前，记得在路由器上把连接端口（默认 UDP `51820`）转发到 NAS 的局域网地址，并在「系统设置 → 接入设置」填写家里的公网地址。

## 界面与功能

```
总览       实时流量、连接与设备状态、系统状态卡、新手引导
我的连接   创建/编辑/启停连接、地址端口 MTU DNS、场景预设、导入导出
我的设备   设备管理、二维码、上网方式、使用期限、配额
运行记录   操作审计与系统日志
系统维护   一键体检、异常清单、网络修复、内网访问诊断、残留网卡清理、重新应用
系统设置   接入设置、账号管理、备份还原、关于
```

- **系统状态栏**：顶栏常驻红/黄/绿状态点，异常时点击直达「系统维护」。
- **异常横幅**：只要存在「功能确实没在工作」的问题，页面顶部会常驻横幅，可一键修复或跳转处理。
- **配置说明大全**：每个配置项都有「是什么 / 为什么 / 有什么影响 / 例子」的白话说明。

## 命令行工具

安装后 `fnwg-cli` 软链到 `/usr/local/bin/fnwg-cli`：

```bash
sudo /usr/local/bin/fnwg-cli status                  # 连接与设备实时状态
sudo /usr/local/bin/fnwg-cli netcheck                # 系统上网路线 + 内网访问链路 + 疑似残留网卡
sudo /usr/local/bin/fnwg-cli cleanup                 # 删除本应用创建的全部网络对象
sudo /usr/local/bin/fnwg-cli cleanup-foreign <名称>  # 清理不是本应用创建的 WireGuard 网卡
sudo /usr/local/bin/fnwg-cli reconcile               # 立即把配置下发到内核
sudo /usr/local/bin/fnwg-cli export --all --out DIR  # 导出全部连接的 wg-quick 配置
sudo /usr/local/bin/fnwg-cli version                 # 版本信息
```

> `sudo` 按自己的 `secure_path` 查找命令，若报 `command not found`，用绝对路径即可。

## 数据与隐私

- 全部配置、密钥、日志均保存在 NAS 本机（`@appdata/fn-wireguard`），不联网上传。
- 私钥与口令落盘前用 AES-256-GCM 加密；登录口令用 argon2id 哈希。
- 不采集、不外传任何个人数据；只有你主动配置告警 Webhook 时才向指定地址发送通知。

## 常见问题

### Q1. 装完 NAS 上不了网（FN Connect 失效、应用市场打不开）

这通常是**旧版本（≤ 0.2.0）**的残留路由所致，0.3.0 起已从代码层禁止此类行为。先看现象：

```bash
ip route show default                 # 是否多了 default dev wg0
sudo /usr/local/bin/fnwg-cli cleanup  # 删除本应用创建的全部对象
```

系统原本的默认路由并没有被删除，无需手工加回。

### Q2. 设备连上了，能访问 NAS，但访问不了家里其它设备

先看「我的连接」里该连接的**「访问家里内网」**开关是否打开；若已打开仍不通，到 **系统维护 → 内网访问诊断**，会逐项告诉你卡在哪一层（开关 / 设备通行范围 / 转发规则 / 内核转发 / 系统转发链 / 出口网卡）。

### Q3. 系统里有两个 wg0 / wg1 网卡不能用，还占着端口

它们是**历史残留**（不是当前应用创建的），应用出于安全拒绝接管。到 **系统维护 → 疑似残留网卡** 清理（会要求输入网卡名二次确认，且只允许删除 WireGuard 类型的网卡）。

### Q4. 内网访问提示「未能探测到出口网卡」

说明 NAS 的默认路由没能被识别。到 **系统维护** 查看「出口网卡」一项的具体原因：没有默认路由 / 出口指向隧道 / 网卡未启用，按提示处理即可。

### Q5. `sudo fnwg-cli netcheck` 提示 `command not found`

不是没装，是 `sudo` 的查找路径和你的 shell 不一样，用绝对路径 `/usr/local/bin/fnwg-cli` 即可。

### Q6. 卸载会丢配置吗？

不会。卸载默认保留数据目录，重装后自动恢复；但会清理本应用创建的内核对象，不留痕迹。

## 构建与开发

环境：Go 1.24、Node 20、[fnpack](https://developer.fnnas.com/docs/cli/fnpack)。

```bash
./scripts/version.sh show                  # 查看当前版本
./scripts/version.sh patch "改动说明"      # 升补丁版本
make release MSG="改动说明"                # 升版本 + 打双架构包
./scripts/build.sh all                     # 打双架构安装包
```

- 版本号唯一来源：`apps/fn-wireguard/manifest` 的 `version`；`version.sh` 会同步前端工程与 README。
- 干净克隆即可 `go build ./...` / `go test ./...`（前端产物用构建标签 `embedui` 控制，发布构建自动内嵌）。
- 打 tag 推送到 GitHub 后，Actions 自动校验版本、跑测试、双架构打包并创建 Release。

```bash
git tag -a v0.6.0 -m "fn-WireGuard v0.6.0"
git push origin v0.6.0
```

## 版本规划

详见 [docs/ROADMAP.md](docs/ROADMAP.md)。已发布的版本：

- **0.3.x** 安全加固、多连接、异地组网
- **0.4.0** 稳定性与残留治理
- **0.5.x** 内网访问（设备访问家里其它设备）
- **0.6.0** 界面整合与状态可见性

规划中：0.7.0 访问控制、0.8.0 内网体验、0.9.0 兼容性、1.0.0 正式版。

## 参与贡献

欢迎提交 Issue 与 Pull Request。

### 分支与发版流程

日常开发一律在 `dev` 分支进行，只有「形成一个新版本」时才合回 `main` 并打 tag 发版：

```bash
git checkout dev                 # 日常都在 dev 上开发
# ... 开发、提交若干次 ...
git push origin dev

# 新版本定型后，合入 main 并发版
git checkout main
git merge dev                    # 或 git merge --no-ff dev 保留合并记录
./scripts/version.sh show        # 确认版本号
git push origin main
git tag -a v0.7.0 -m "..." && git push origin v0.7.0   # 触发 Release
```

约定：

- **`main` 只放已定型的版本**，不发版不直接往 `main` 提交。
- **`dev` 是唯一长期开发分支**，功能分支建议从 `dev` 拉出、完成后合回 `dev`。
- **每次改动先 bump 版本**（`./scripts/version.sh patch "..."`），版本号与提交一起走。
- 打 `v*` tag 会自动触发 `.github/workflows/release.yml` 校验版本 → 测试 → 双架构打包 → 创建 Release。

### 贡献须知

- 提交 Issue 前请附上：fnOS 版本、`uname -m`、`sudo /usr/local/bin/fnwg-cli netcheck` 输出、相关日志。
- 涉及网络行为的改动，请务必补充 `internal/wgback/routesafety_test.go` 与 `internal/wgback/natplan_test.go` 中的回归用例。
- 修改配置项文案只需编辑 `frontend/src/constants/fields.ts`，界面会自动同步。

### 提交前自检

```bash
test -z "$(gofmt -l .)" && go vet ./... && go test ./...
cd frontend && npx vue-tsc --noEmit && npm run build
```

## License

[MIT](LICENSE) © [newcdl](https://github.com/newcdl)
