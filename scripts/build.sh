#!/usr/bin/env bash
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
        build_frontend
        build_backend "$(go env GOARCH)"
        ;;
    amd64)
        guard_version_not_built
        build_frontend
        build_backend amd64
        package_fpk amd64 x86
        ;;
    arm64)
        guard_version_not_built
        build_frontend
        build_backend arm64
        package_fpk arm64 arm
        ;;
    all)
        guard_version_not_built
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
