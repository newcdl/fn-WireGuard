// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

//go:build !embedui

// Package webui 的默认（开发）实现：不内嵌任何前端产物，
// 保证刚克隆的仓库在未安装 Node / 未构建前端时也能直接 go build 与 go test。
package webui

import (
	"io/fs"
	"testing/fstest"
)

const placeholderHTML = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WireGuard 管理工具 · 前端尚未构建</title>
<style>
  :root { color-scheme: light dark; }
  body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
         font-family:-apple-system,BlinkMacSystemFont,"PingFang SC","Microsoft YaHei",sans-serif;
         background:#f5f7fa; color:#303133; padding:24px; }
  @media (prefers-color-scheme: dark) { body { background:#14161a; color:#e5e7eb; } }
  .card { max-width:640px; background:rgba(127,127,127,.08); border:1px solid rgba(127,127,127,.25);
          border-radius:14px; padding:28px 32px; line-height:1.8; }
  h1 { margin:0 0 6px; font-size:20px; }
  p  { margin:8px 0; }
  code { background:rgba(127,127,127,.16); padding:2px 6px; border-radius:5px; font-size:13px; }
  pre { background:rgba(127,127,127,.12); padding:12px 14px; border-radius:10px; overflow:auto; font-size:13px; }
  .muted { opacity:.65; font-size:13px; }
</style>
</head>
<body>
  <div class="card">
    <h1>前端尚未构建</h1>
    <p>当前运行的是未内嵌前端的开发版后端。请先构建前端，再重新编译：</p>
    <pre>./scripts/build.sh</pre>
    <p class="muted">或者只构建前端：</p>
    <pre>cd frontend &amp;&amp; npm install &amp;&amp; npm run build
rm -rf internal/webui/dist &amp;&amp; cp -R frontend/dist internal/webui/dist
go build -tags embedui -o bin/fnwg-web ./cmd/fnwg-web</pre>
    <p class="muted">后端 API 已可正常访问：<code>/api/v1/auth/state</code></p>
  </div>
</body>
</html>
`

// FS 返回占位页面。
func FS() (fs.FS, error) {
	return fstest.MapFS{
		"index.html": &fstest.MapFile{Data: []byte(placeholderHTML)},
	}, nil
}
