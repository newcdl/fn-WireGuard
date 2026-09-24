<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 小柿子 <newxsz@163.com> -->

<!--
  一键诊断包：把「体检 + 巡检 + 拓扑 + 资产 + 连接与设备 + 运行记录 + 审计」打成一个 .tar 下载。
  出问题时不用来回截图，发一个文件就能把现场带过去。

  两点刻意的设计：
    · 在**浏览器端**打包（tar 格式很简单，自己写即可）：不需要后端新增接口、不引任何依赖；
    · 每一份取不到只记在 README 里、不中断打包：半份能用的包，也好过报错什么都没有。
  注意：包里有内网 IP、主机名与运行日志，属于敏感信息，转发前请确认对方可信。
-->
<template>
  <el-button size="small" type="primary" plain :icon="Download" :loading="busy" @click="build">
    一键诊断包
  </el-button>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { ElMessage } from 'element-plus'
import { Download } from '@element-plus/icons-vue'
import { api } from '@/api/client'

const busy = ref(false)

/** 包里装哪些接口的数据（文件名用 ASCII，中文说明写在 README 里，兼容各种解包工具）。 */
const SOURCES: { file: string; url: string; what: string }[] = [
  { file: 'overview.json', url: '/overview', what: '总体概览：连接与设备数量、流量合计、版本等' },
  { file: 'network-check.json', url: '/system/network', what: '网络体检：内核模块、网卡、转发与 NAT、解析服务、内网网段等' },
  { file: 'inspect.json', url: '/system/inspect', what: '配置漂移巡检：计划、最近一次报告与历史' },
  { file: 'topology.json', url: '/topology', what: '网络拓扑的原始数据（节点与连线）' },
  { file: 'assets.json', url: '/assets', what: '内网资产台账：家里有哪些设备、首次与最近出现' },
  { file: 'interfaces.json', url: '/interfaces', what: '连接清单（不含私钥）' },
  { file: 'peers.json', url: '/peers', what: '设备清单（不含密钥）' },
  { file: 'logs.json', url: '/logs', what: '运行记录' },
  { file: 'audit.json', url: '/audit', what: '审计记录' },
]

function nowStamp(): string {
  const d = new Date()
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}`
}

/** 把字符串按 UTF-8 编码成字节。 */
function bytes(s: string): Uint8Array {
  return new TextEncoder().encode(s)
}

/** 写一个 ustar 头（tar 格式很简单：512 字节头 + 内容补齐到 512 的倍数）。 */
function tarHeader(name: string, size: number): Uint8Array {
  const h = new Uint8Array(512)
  const put = (s: string, off: number, len: number) => {
    const b = bytes(s)
    h.set(b.subarray(0, len), off)
  }
  const octal = (v: number, len: number) => v.toString(8).padStart(len - 1, '0') + '\0'
  put(name, 0, 100)
  put(octal(0o644, 8), 100, 8)
  put(octal(0, 8), 108, 8)
  put(octal(0, 8), 116, 8)
  put(octal(size, 12), 124, 12)
  put(octal(Math.floor(Date.now() / 1000), 12), 136, 12)
  // 校验和字段先填空格，算完再写回
  for (let i = 148; i < 156; i++) h[i] = 32
  h[156] = '0'.charCodeAt(0)
  put('ustar', 257, 5)
  put('00', 263, 2)
  put('fnwireguard', 265, 32)
  put('fnwireguard', 297, 32)
  let sum = 0
  for (let i = 0; i < 512; i++) sum += h[i]
  put(sum.toString(8).padStart(6, '0') + '\0 ', 148, 8)
  return h
}

/** 把若干文件打成一个 tar（不压缩：内容都是小 JSON，够用且无需任何依赖）。 */
function buildTar(files: { name: string; data: string }[]): Blob {
  const parts: Uint8Array[] = []
  for (const f of files) {
    const data = bytes(f.data)
    parts.push(tarHeader(f.name, data.byteLength))
    parts.push(data)
    const pad = (512 - (data.byteLength % 512)) % 512
    if (pad) parts.push(new Uint8Array(pad))
  }
  parts.push(new Uint8Array(1024))
  return new Blob(parts as BlobPart[], { type: 'application/x-tar' })
}

async function build(): Promise<void> {
  busy.value = true
  const files: { name: string; data: string }[] = []
  const failed: string[] = []
  for (const s of SOURCES) {
    try {
      const data = await api.get<unknown>(s.url)
      files.push({ name: s.file, data: JSON.stringify(data, null, 2) })
    } catch {
      // 取不到就记下来，不中断：半份能用的包也好过什么都没有
      failed.push(`${s.file}（${s.what}）取不到，可能是权限不足或该功能未启用`)
    }
  }
  const readme = [
    '网络诊断包',
    '',
    `生成时间：${new Date().toLocaleString()}`,
    '说明：本包用于排查问题，包含本应用当前的配置与运行状态快照。',
    '生成方式：由界面在浏览器端打包（tar 格式，未压缩），未上传到任何地方。',
    '',
    '包含内容：',
    ...SOURCES.filter((s) => !failed.some((f) => f.startsWith(s.file))).map((s) => `  ${s.file}  —— ${s.what}`),
    ...(failed.length ? ['', '下面这些没取到：', ...failed.map((f) => `  ${f}`)] : []),
    '',
    '隐私提醒：包内有内网 IP、主机名与运行日志等敏感信息，转发前请确认接收方可信。',
    '（连接与设备清单中的私钥、预共享密钥在服务端就已经被清空，不会出现在包里。）',
    '',
  ].join('\n')
  files.unshift({ name: 'README.txt', data: readme })

  const blob = buildTar(files)
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = `诊断包-${nowStamp()}.tar`
  a.click()
  setTimeout(() => URL.revokeObjectURL(a.href), 5000)
  busy.value = false
  if (failed.length) ElMessage.warning(`已生成（有 ${failed.length} 项没取到，见包里 README）`)
  else ElMessage.success('诊断包已生成')
}
</script>
