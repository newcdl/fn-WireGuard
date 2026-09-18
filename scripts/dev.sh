#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 小柿子 <newxsz@163.com>

# 本地开发脚本：在开发机上以内存后端运行，便于调试 UI 与业务流程（不会操作真实网络）。
#
# 用法:
#   ./scripts/dev.sh           # 构建并启动（http://127.0.0.1:18080）
#   ./scripts/dev.sh frontend  # 启动 Vite 开发服务器（热更新，代理到 18080）
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

DEV_DIR="${DEV_DIR:-/tmp/fnwg-dev}"
PORT="${PORT:-18080}"

if [ "${1:-run}" = "frontend" ]; then
    cd frontend
    [ -d node_modules ] || npm install --no-audit --no-fund
    echo "Vite 开发服务器: http://127.0.0.1:5273 （API 代理到 ${PORT}）"
    exec npm run dev
fi

mkdir -p "$DEV_DIR"

# 开发模式同样需要内嵌前端；若尚未构建则先构建一次
if [ ! -f internal/webui/dist/index.html ]; then
    echo "首次运行：先构建前端静态资源…"
    (cd frontend && [ -d node_modules ] || npm install --no-audit --no-fund) && (cd frontend && npm run build)
    rm -rf internal/webui/dist
    cp -R frontend/dist internal/webui/dist
fi

go build -tags embedui -o bin/fnwg-web ./cmd/fnwg-web

echo "开发模式启动中：http://127.0.0.1:${PORT}"
echo "默认账号：admin / admin12345（仅首次自动创建）"
echo "数据目录：${DEV_DIR}"
exec ./bin/fnwg-web --dev \
    --var "$DEV_DIR" \
    --etc "$DEV_DIR/etc" \
    --home "$DEV_DIR/home" \
    --port "$PORT"
