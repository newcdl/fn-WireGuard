#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 newcdl <newcdl@163.com>

# fn-WireGuard 构建脚本
#
# 用法:
#   ./scripts/build.sh                # 构建前端 + 当前机器架构的 linux 二进制（不做 fpk 打包）
#   ./scripts/build.sh amd64          # 构建并打包 linux/amd64 的 fpk
#   ./scripts/build.sh arm64          # 构建并打包 linux/arm64 的 fpk
#   ./scripts/build.sh all            # 同时构建两个架构的 fpk（两个文件，即发布用产物）
#
# 发布形态固定为「每个架构一个包」：飞牛应用中心按 manifest 的 platform 字段挑包，
# 一份包只能声明一个平台，因此发布就是 x86 与 arm 各一个 fpk，不提供通用包。
#
# 依赖: Go 1.24+、Node 20+、fnpack（https://developer.fnnas.com/docs/cli/fnpack/）
#
# 产物布局遵循 fnpack 规范：应用运行时内容放在 app/ 目录，由 fnpack 打包为 app.tgz
# 并解压到设备上的 target/（即 TRIM_APPDEST）。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

APP_NAME="fn-wireguard"
APP_DIR="apps/${APP_NAME}"
APP_PAYLOAD="${APP_DIR}/app"
DIST_DIR="dist"
VERSION="$(sed -n 's/^version[[:space:]]*=[[:space:]]*//p' "${APP_DIR}/manifest" | head -1)"
VERSION="${VERSION:-0.1.0}"
BUILD_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LDFLAGS="-s -w -X main.buildVersion=${VERSION}"

log() { printf '\033[1;34m[build]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[build]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[build]\033[0m %s\n' "$*" >&2; exit 1; }

find_fnpack() {
    if command -v fnpack >/dev/null 2>&1; then
        command -v fnpack
        return 0
    fi
    for p in "$HOME/bin/fnpack" /usr/local/bin/fnpack "$ROOT/tools/fnpack"; do
        [ -x "$p" ] && { echo "$p"; return 0; }
    done
    return 1
}

# ---------------------------------------------------------------- 前端
build_frontend() {
    log "构建前端静态资源"
    if [ ! -d frontend/node_modules ]; then
        (cd frontend && npm install --no-audit --no-fund)
    fi
    (cd frontend && npm run build)
    rm -rf internal/webui/dist
    cp -R frontend/dist internal/webui/dist
    log "前端资源已内嵌到 internal/webui/dist"
}

# ---------------------------------------------------------------- 后端
# clean_payload 清掉上一次构建留下的二进制。
#
# 每目标开建前都清一次是有意的：切换架构构建时，若上一次的二进制残留在目录里，
# 会被打进别的架构的包内，包体积翻倍且出现两份同名能力，
# 属于「只在切换构建目标时才出现」的隐蔽故障。
#
# 只删构建产物、绝不用 rm -rf 整个目录：载荷目录里同时住着**源码**
# （app/ui 下的图标与桌面入口配置，仓库跟踪它们），整目录删掉会把源码一起带走，
# 而且打包会在很远的地方以「app/ui: no such file or directory」的形式失败，
# 与真正的过错（这条命令）隔了一层。删除范围严格等于 .gitignore 里列的那两条。
clean_payload() {
    mkdir -p "${APP_PAYLOAD}"
    rm -f "${APP_PAYLOAD}"/fnwg-* "${APP_PAYLOAD}/BUILDINFO"
}

# compile_binaries <goarch>
# 产出 target 下的正式名字（无架构后缀）：包与架构一一对应，平台由 manifest 的 platform 声明。
compile_binaries() {
    local arch="$1"
    log "编译 linux/${arch} 二进制"
    local bin
    for bin in fnwg-agent fnwg-web fnwg-cli; do
        # -tags embedui：把前端产物真正内嵌进 fnwg-web（干净克隆默认走占位实现）
        GOOS=linux GOARCH="$arch" CGO_ENABLED=0 \
            go build -trimpath -tags embedui -ldflags "$LDFLAGS" \
            -o "${APP_PAYLOAD}/${bin}" "./cmd/${bin}"
    done
    chmod +x "${APP_PAYLOAD}"/fnwg-*
}

# write_buildinfo <arch 描述>
write_buildinfo() {
    {
        echo "appname=${APP_NAME}"
        echo "version=${VERSION}"
        echo "arch=$1"
        echo "built_at=${BUILD_TIME}"
    } > "${APP_PAYLOAD}/BUILDINFO"
}

# build_backend <goarch>
build_backend() {
    local arch="$1"
    clean_payload
    compile_binaries "$arch"
    write_buildinfo "$arch"
    ls -lh "${APP_PAYLOAD}"
}

# ---------------------------------------------------------------- 版本号防呆
# 约定：任何影响安装包内容的改动，都应先 bump 版本再打包，这样设备上装的版本
# 与日志、更新说明始终对得上。
#
# 这里在**构建之前**直接失败，而不是打包时警告一句：同版本的包在应用中心里升不上去，
# 覆盖重打的结果是「改了半天，装到设备上还是旧的那一个」；只提醒不拦截挡不住这件事
# —— 它和日志里那句被忽略的警告是同一类失效。
# 确实需要原地重打（例如只想验证打包流程）时用 FNWG_ALLOW_REBUILD=1 显式放行。
guard_version_not_built() {
    compgen -G "${DIST_DIR}/${APP_NAME}-${VERSION}-*.fpk" >/dev/null 2>&1 || return 0
    if [ "${FNWG_ALLOW_REBUILD:-}" = "1" ]; then
        warn "版本 ${VERSION} 已有安装包，按 FNWG_ALLOW_REBUILD=1 覆盖重打"
        return 0
    fi
    die "版本 ${VERSION} 的安装包已存在（${DIST_DIR}/${APP_NAME}-${VERSION}-*.fpk）
       同版本的包在设备上无法升级（会被当作同一个版本），覆盖重打会让本次改动静默失效。
       请先推进版本号：./scripts/version.sh patch \"这次改了什么\"
       若确实要原地重打，请显式放行：FNWG_ALLOW_REBUILD=1 ./scripts/build.sh ${TARGET}"
}

# ---------------------------------------------------------------- 校验
# run_tests：打包前必跑，绑进流程而不是留在开发者的记忆里。
#
# 打包会覆盖载荷目录并产出**能直接装到设备上**的产物；一旦某次「先跳过测试、
# 待会儿再补」，坏掉的包已经在 dist 里了。更麻烦的是版本号此时已经 bump，
# 事后修好还得再 bump 一次，设备上才会出现新版本 —— 代价远高于跑一次测试。
#
# go vet 一并放在这里：它抓的是「能编译、但明显不对」的调用，几秒钟的成本，
# 常常比单元测试更早发现笔误。
# 需要快速迭代时可以 FNWG_SKIP_TESTS=1 显式跳过（发布时不要用）。
run_tests() {
    if [ "${FNWG_SKIP_TESTS:-}" = "1" ]; then
        warn "按 FNWG_SKIP_TESTS=1 跳过测试（仅限本地迭代，发布勿用）"
        return 0
    fi
    log "运行后端静态检查与单元测试"
    "$GO_BIN" vet ./...
    "$GO_BIN" test ./...
    log "运行前端类型检查"
    if [ ! -d frontend/node_modules ]; then
        (cd frontend && npm install --no-audit --no-fund)
    fi
    (cd frontend && npm run typecheck)
}

# verify_fpk <文件> <goarch> <platform>：验收刚打出来的包。
#
# 打包不是「命令没报错就对了」：载荷里的二进制是复用上一次构建结果的，
# 平台信息靠 sed 改写 manifest，载荷由 app/ 经 fnpack 二次封装 —— 任何一步出岔子，
# 产物都「看起来成功」但装到设备上是另一个架构或另一个版本，
# 这类问题只有真把包解开核对才能发现。
# 因此这里拆包，逐个核对真正决定设备行为的东西：
#   1. manifest 的 version / platform：决定应用中心让不让升级、装到哪台设备
#   2. 载荷里三个二进制的真实架构：决定装上去能不能执行
#   3. 桌面入口的 gatewaySocket：缺了它从飞牛桌面打开就是 502
#   4. 安装/升级脚本存在且可执行：缺了它装完不会授权网关 socket
verify_fpk() {
    local fpk="$1" arch="$2" platform="$3"
    [ -s "$fpk" ] || die "产物为空: $fpk"
    local expect
    case "$arch" in
        amd64) expect='x86-64' ;;
        arm64) expect='aarch64' ;;
        *) die "未知架构: $arch" ;;
    esac

    local tmp="${DIST_DIR}/.verify-${arch}"
    rm -rf "$tmp"
    mkdir -p "$tmp"

    tar -xf "$fpk" -C "$tmp" || die "无法解开产物（不是预期的 fpk 结构）: $fpk"
    [ -f "$tmp/manifest" ] || die "$fpk 内缺少 manifest"
    grep -q "^version[[:space:]]*=[[:space:]]*${VERSION}$" "$tmp/manifest" \
        || die "$fpk 的 manifest 版本与 ${VERSION} 不一致"
    grep -q "^platform[[:space:]]*=[[:space:]]*${platform}$" "$tmp/manifest" \
        || die "$fpk 的 manifest platform 不是 ${platform}"

    local script
    for script in install_init install_callback upgrade_init upgrade_callback uninstall_init; do
        [ -f "$tmp/cmd/$script" ] || die "$fpk 内缺少 cmd/$script"
        [ -x "$tmp/cmd/$script" ] || die "$fpk 内 cmd/$script 没有执行权限"
    done

    [ -f "$tmp/app.tgz" ] || die "$fpk 内缺少载荷 app.tgz"
    tar -xzf "$tmp/app.tgz" -C "$tmp" || die "$fpk 的载荷 app.tgz 无法解开"

    local bin
    for bin in fnwg-agent fnwg-web fnwg-cli; do
        [ -s "$tmp/$bin" ] || die "载荷内缺少 $bin"
        file "$tmp/$bin" | grep -q "$expect" \
            || die "载荷内 $bin 的架构不是 ${arch}：$(file -b "$tmp/$bin")"
    done
    grep -q "^arch=${arch}$" "$tmp/BUILDINFO" || die "载荷内 BUILDINFO 的架构不是 ${arch}"

    [ -f "$tmp/ui/config" ] || die "载荷内缺少桌面入口 ui/config"
    grep -q '"gatewaySocket"[[:space:]]*:[[:space:]]*"app.sock"' "$tmp/ui/config" \
        || die "桌面入口 ui/config 缺少 gatewaySocket=app.sock（从飞牛桌面打开会显示 502）"

    # GPL 全文必须在包里。这是许可合规的验收项，不是可选项：
    # fnpack 只保留它认识的条目，我们放在包根的 COPYING 会被静默丢弃（实测如此），
    # 因此正文走载荷 app.tgz 进包 —— 这条断言防的就是「某次改动之后它又悄悄没了」。
    [ -f "$tmp/COPYING" ] || die "$fpk 内缺少 COPYING（GPL 全文未随包分发）"
    grep -q "GNU GENERAL PUBLIC LICENSE" "$tmp/COPYING" \
        || die "$fpk 内的 COPYING 不是 GPL 全文"

    rm -rf "$tmp"
    log "已验收 ${fpk}：版本 ${VERSION} / 平台 ${platform} / 载荷架构 ${arch}"
}

# ---------------------------------------------------------------- 打包
# package_fpk <goarch> <platform>
package_fpk() {
    local arch="$1" platform="$2" fnpack
    if ! fnpack="$(find_fnpack)"; then
        warn "未检测到 fnpack，跳过 fpk 打包"
        warn "下载: https://static2.fnnas.com/fnpack/fnpack-1.2.3-<darwin|linux>-<amd64|arm64>"
        return 0
    fi
    log "打包 ${arch} 安装包（$("$fnpack" --help 2>&1 | sed -n 's/^Version //p' | head -1)）"

    local stage_root="${DIST_DIR}/stage-${arch}"
    local stage="${stage_root}/${APP_NAME}"
    rm -rf "$stage_root"
    mkdir -p "$stage"
    # 只拷贝包所需内容，排除构建产物缓存
    (cd "$APP_DIR" && tar cf - --exclude='*.fpk' .) | (cd "$stage" && tar xf -)

    # GPL 全文随载荷进包。
    #
    # 为什么不直接放在包根（apps/fn-wireguard/COPYING 就放在那儿）：fnpack 打包时
    # 只保留 manifest / LICENSE / cmd / config / wizard / ICON / app.tgz，包根的 COPYING
    # 会被**静默丢弃**（实测确认），于是「仓库里有全文、装到设备上却没有」。
    # 放进 app/ 则不同：app.tgz 里的文件会原样解到应用运行目录，设备上直接可见。
    #
    # 源头仍只有一份（apps/fn-wireguard/COPYING），这里只是搬运 ——
    # 不复制出第二份需要人肉同步的副本。
    cp "${APP_DIR}/COPYING" "$stage/app/COPYING" || die "缺少 ${APP_DIR}/COPYING（GPL 全文）"

    # 按目标架构改写 manifest（platform: x86 / arm），并写入真实包体积
    local payload_mb
    payload_mb="$(du -sm "$stage" | awk '{print $1}')"
    sed -i.bak -e "s/^platform[[:space:]]*=.*/platform              = ${platform}/" \
        -e "s/^size[[:space:]]*=.*/size                  = ${payload_mb}/" \
        "$stage/manifest"
    rm -f "$stage/manifest.bak"
    chmod +x "$stage/cmd"/* "$stage/app"/fnwg-* 2>/dev/null || true

    (cd "$stage" && "$fnpack" build) || die "fnpack 打包失败"

    local produced
    produced="$(find "$stage" -maxdepth 1 -name '*.fpk' | head -1)"
    [ -n "$produced" ] || die "未找到 fnpack 产出的 .fpk 文件"
    mkdir -p "$DIST_DIR"
    local out="${DIST_DIR}/${APP_NAME}-${VERSION}-${arch}.fpk"
    mv "$produced" "$out"
    # 在删掉 stage 之前验收：此时载荷已被 fnpack 二次封装过，验的是用户真正装的那个文件。
    verify_fpk "$out" "$arch" "$platform"
    rm -rf "$stage_root"
    log "已生成 ${out}（$(du -h "$out" | awk '{print $1}')）"
}

# ---------------------------------------------------------------- 主流程
GO_BIN="${GO_BIN:-$(command -v go || echo "$HOME/go-sdk/go/bin/go")}"
[ -x "$GO_BIN" ] || die "未找到 go 可执行文件，请安装 Go 1.24+ 或设置 GO_BIN 环境变量"
export PATH="$(dirname "$GO_BIN"):$PATH"

TARGET="${1:-local}"
case "$TARGET" in
    local)
        run_tests
        build_frontend
        build_backend "$(go env GOARCH)"
        ;;
    amd64)
        guard_version_not_built
        run_tests
        build_frontend
        build_backend amd64
        package_fpk amd64 x86
        ;;
    arm64)
        guard_version_not_built
        run_tests
        build_frontend
        build_backend arm64
        package_fpk arm64 arm
        ;;
    all)
        guard_version_not_built
        # 测试只跑一次：两个架构共用同一份源码，跑两遍只是浪费时间，
        # 但一定要在**两个包都产出之前**跑完，才能挡住带病发布。
        run_tests
        build_frontend
        build_backend amd64
        package_fpk amd64 x86
        build_backend arm64
        package_fpk arm64 arm
        ;;
    *)
        die "未知目标: $TARGET（可选 local / amd64 / arm64 / all）"
        ;;
esac

log "构建完成（版本 ${VERSION}）"
