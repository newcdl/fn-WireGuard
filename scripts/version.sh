#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 小柿子 <newxsz@163.com>

# fn-WireGuard 版本号管理
#
# 用法:
#   ./scripts/version.sh show                      # 显示当前版本
#   ./scripts/version.sh patch "这次改了什么"        # 0.3.0 → 0.3.1（并写入更新说明）
#   ./scripts/version.sh minor "这次改了什么"        # 0.3.1 → 0.4.0
#   ./scripts/version.sh major "这次改了什么"        # 0.4.0 → 1.0.0
#   ./scripts/version.sh set 1.0.0 "说明"           # 直接指定版本号
#
# 版本号的唯一来源是 apps/fn-wireguard/manifest 的 version 字段，
# 本脚本负责把它同步到前端工程与 README，避免多处不一致。
#
# 约定：任何会影响安装包内容的改动，都应先 bump 再打包，
#       这样设备上装的哪个版本、日志里报的是哪个版本始终对得上。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

APP_DIR="apps/fn-wireguard"
MANIFEST="${APP_DIR}/manifest"
README="README.md"
FRONTEND="frontend"

log()  { printf '\033[1;34m[version]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[version]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[version]\033[0m %s\n' "$*" >&2; exit 1; }

[ -f "$MANIFEST" ] || die "未找到 $MANIFEST，请在仓库根目录运行"

read_version() {
    sed -n 's/^version[[:space:]]*=[[:space:]]*//p' "$MANIFEST" | head -1
}

valid_version() {
    printf '%s' "$1" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'
}

next_version() { # <当前版本> <patch|minor|major>
    local cur="$1" kind="$2" major minor patch
    IFS=. read -r major minor patch <<< "$cur"
    case "$kind" in
        major) major=$((major + 1)); minor=0; patch=0 ;;
        minor) minor=$((minor + 1)); patch=0 ;;
        patch) patch=$((patch + 1)) ;;
        *) die "未知的递增类型: $kind" ;;
    esac
    printf '%s.%s.%s' "$major" "$minor" "$patch"
}

# manifest 的字段名统一左对齐到该宽度后再跟 " = "，保持文件原有版式
MANIFEST_FIELD_WIDTH=21

# 改写 manifest 的单行字段（awk 的 -v 传值不受特殊字符影响，避免 sed 转义踩坑）
set_manifest_field() { # <字段名> <值>
    local field="$1" value="$2" tmp
    tmp="$(mktemp)"
    awk -v f="$field" -v v="$value" -v w="$MANIFEST_FIELD_WIDTH" '
        $0 ~ "^" f "[[:space:]]*=" { printf "%-*s = %s\n", w, f, v; next }
        { print }
    ' "$MANIFEST" > "$tmp"
    cat "$tmp" > "$MANIFEST"
    rm -f "$tmp"
}

# 在 changelog 开头插入本次更新说明（保留历史记录）
prepend_changelog() { # <版本> <说明>
    local ver="$1" note="$2" entry tmp
    entry="${ver} ${note}。"
    tmp="$(mktemp)"
    awk -v entry="$entry" -v w="$MANIFEST_FIELD_WIDTH" '
        /^changelog[[:space:]]*=/ {
            sub(/^changelog[[:space:]]*=[[:space:]]*/, "")
            printf "%-*s = %s%s\n", w, "changelog", entry, $0
            next
        }
        { print }
    ' "$MANIFEST" > "$tmp"
    cat "$tmp" > "$MANIFEST"
    rm -f "$tmp"
}

apply_version() { # <新版本> <说明>
    local new="$1" note="$2" old
    old="$(read_version)"

    set_manifest_field version "$new"
    # 仅在版本号真的变化时追加更新说明，重复执行同一版本不会写重
    if [ -n "$note" ] && [ "$old" != "$new" ]; then
        prepend_changelog "$new" "$note"
    fi

    # 前端工程版本（npm 会同时更新 package.json 与 package-lock.json）
    if [ -f "${FRONTEND}/package.json" ]; then
        if command -v npm >/dev/null 2>&1; then
            (cd "$FRONTEND" && npm version "$new" --no-git-tag-version --allow-same-version >/dev/null)
        else
            warn "未检测到 npm，跳过前端版本同步"
        fi
    fi

    # README 里只替换安装包文件名中的版本，不碰历史说明（例如「该问题已在 0.3.0 修复」）
    if [ -f "$README" ] && [ "$old" != "$new" ]; then
        sed -i.bak "s/fn-wireguard-${old}-/fn-wireguard-${new}-/g" "$README"
        rm -f "${README}.bak"
    fi

    log "版本 ${old} → ${new}"
    # 注意用 if 而不是 `[ -n ... ] && log`：后者在不带说明时会成为函数最后一条语句，
    # 返回非零进而让整个脚本以失败退出。
    if [ -n "$note" ]; then
        log "更新说明：${note}"
    fi
}

case "${1:-show}" in
    show)
        log "当前版本：$(read_version)"
        ;;
    patch | minor | major)
        cur="$(read_version)"
        valid_version "$cur" || die "manifest 中的版本号格式不正确: $cur"
        apply_version "$(next_version "$cur" "$1")" "${2:-}"
        ;;
    set)
        [ -n "${2:-}" ] || die "请指定版本号，例如 ./scripts/version.sh set 1.0.0"
        valid_version "$2" || die "版本号需为 x.y.z 形式，例如 1.0.0"
        apply_version "$2" "${3:-}"
        ;;
    *)
        die "未知命令: $1（可选 show / patch / minor / major / set）"
        ;;
esac
