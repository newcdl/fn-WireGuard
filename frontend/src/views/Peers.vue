<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 小柿子 <newxsz@163.com> -->

<template>
  <div>
    <div class="fnwg-toolbar">
      <el-select v-model="ifaceFilter" placeholder="全部连接" clearable style="width: 160px" @change="load">
        <el-option v-for="it in interfaces" :key="it.id" :label="it.name" :value="it.id" />
      </el-select>
      <el-input v-model="keyword" placeholder="搜索设备名称" clearable style="width: 180px" />
      <el-button v-if="session.can('peer.write')" type="primary" :icon="Plus" @click="openCreate">
        添加设备
      </el-button>
      <el-button v-if="session.can('peer.write')" :icon="Upload" @click="openImport">批量导入</el-button>
      <el-dropdown v-if="session.can('peer.write')" :disabled="!selectedIds.length" @command="batch">
        <el-button :disabled="!selectedIds.length">
          批量操作（{{ selectedIds.length }}）<el-icon><ArrowDown /></el-icon>
        </el-button>
        <template #dropdown>
          <el-dropdown-menu>
            <el-dropdown-item command="enable">启用所选设备</el-dropdown-item>
            <el-dropdown-item command="disable">停用所选设备（临时收回权限）</el-dropdown-item>
            <el-dropdown-item command="keepalive" divided>统一设置心跳间隔</el-dropdown-item>
            <el-dropdown-item command="group">统一设置分组标签</el-dropdown-item>
            <el-dropdown-item command="extend">统一延长使用期限</el-dropdown-item>
            <el-dropdown-item command="quota">统一设置流量上限</el-dropdown-item>
            <el-dropdown-item command="delete" divided>永久删除所选设备</el-dropdown-item>
          </el-dropdown-menu>
        </template>
      </el-dropdown>
      <el-button :icon="Refresh" @click="load">刷新</el-button>
      <el-button :icon="Reading" @click="helpVisible = true">配置说明</el-button>
      <div style="flex: 1"></div>
      <el-tag size="small" type="info" effect="plain">在线 {{ onlineCount }} / 共 {{ filtered.length }} 台</el-tag>
    </div>

    <!-- 桌面端：表格 -->
    <div v-if="!isMobile" class="fnwg-card">
      <el-table
        :data="filtered"
        v-loading="loading"
        row-key="id"
        empty-text="还没有设备，点击「添加设备」开始"
        @selection-change="onSelectionChange"
      >
        <el-table-column type="selection" width="46" />
        <el-table-column label="设备" min-width="150">
          <template #default="{ row }">
            <span :class="['fnwg-dot', handshakeLevel(row.last_handshake)]"></span>
            <strong>{{ row.name }}</strong>
            <el-tag v-if="!row.enabled" size="small" type="info" effect="plain" style="margin-left: 6px">已停用</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="状态" width="90">
          <template #default="{ row }">
            <el-tag size="small" :type="stateTagType(row)" effect="plain">{{ stateLabel(row) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="配置" width="110">
          <template #default="{ row }">
            <!-- 「通行范围 / 对外地址」这类设置写在设备里，改完必须重新导入。
                 不主动说的话，用户会以为改完就生效了。 -->
            <el-tooltip
              v-if="row.config_stale"
              content="你在界面上改过的设置（对外地址、通行范围等）还没进入这台设备。点这里重新扫码导入即可生效。"
              placement="top"
            >
              <el-tag
                size="small"
                type="warning"
                effect="plain"
                style="cursor: pointer"
                @click="showConfig(row)"
              >
                需重新扫码
              </el-tag>
            </el-tooltip>
          </template>
        </el-table-column>
        <el-table-column prop="interface_name" label="所属连接" width="100" />
        <el-table-column label="允许访问" min-width="170">
          <template #default="{ row }">
            <span class="fnwg-mono">{{ describeAllowed(row.allowed_ips) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="最近通信" width="110">
          <template #default="{ row }">{{ timeAgo(row.last_handshake) }}</template>
        </el-table-column>
        <el-table-column label="累计流量" width="160">
          <template #default="{ row }">
            ↓{{ formatBytes(row.rx_bytes) }} ↑{{ formatBytes(row.tx_bytes) }}
          </template>
        </el-table-column>
        <el-table-column label="本月用量" width="170">
          <template #default="{ row }">
            <!-- 有额度才画进度条：不限额的设备显示一个「用了多少」就够了，
                 加一条永远不动的空进度条只会让人以为设置没生效。 -->
            <template v-if="usage[row.id]">
              <span :class="{ 'fnwg-over-quota': overQuota(row.id) }">
                {{ formatBytes(usage[row.id].month_tx_bytes) }}
              </span>
              <span v-if="usage[row.id].quota_tx > 0" class="fnwg-hint">
                / {{ formatBytes(usage[row.id].quota_tx) }}
              </span>
              <el-progress
                v-if="usage[row.id].quota_tx > 0"
                :percentage="usagePercent(row.id)"
                :status="overQuota(row.id) ? 'exception' : undefined"
                :show-text="false"
                :stroke-width="6"
                style="margin-top: 2px"
              />
            </template>
            <span v-else class="fnwg-hint">-</span>
          </template>
        </el-table-column>
        <el-table-column label="有效期" width="90">
          <template #default="{ row }">
            <span v-if="!row.expire_at">长期</span>
            <el-tag v-else size="small" :type="(daysLeft(row.expire_at) ?? 0) <= 3 ? 'danger' : 'info'" effect="plain">
              剩 {{ daysLeft(row.expire_at) }} 天
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="220" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" @click="showConfig(row)">扫码连接</el-button>
            <el-button v-if="session.can('peer.write')" link type="primary" @click="openEdit(row)">编辑</el-button>
            <el-button v-if="session.can('peer.write')" link type="danger" @click="remove(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <!-- 移动端：卡片列表 -->
    <div v-else v-loading="loading">
      <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px">
        <el-button size="small" @click="selectAll">
          {{ selectedIds.length === filtered.length && filtered.length ? '取消全选' : '全选' }}
        </el-button>
        <span style="font-size: 12px; opacity: 0.65">已选 {{ selectedIds.length }} 台</span>
      </div>

      <ItemCard
        v-for="row in filtered"
        :key="row.id"
        :status="handshakeLevel(row.last_handshake)"
        :title="row.name"
        selectable
        :selected="selectedIds.includes(row.id)"
        @toggle="toggleSelect(row.id)"
      >
        <template #extra>
          <el-tag size="small" :type="stateTagType(row)" effect="plain">{{ stateLabel(row) }}</el-tag>
          <el-tag v-if="!row.enabled" size="small" type="info" effect="plain">已停用</el-tag>
          <el-tag v-if="row.config_stale" size="small" type="warning" effect="plain">需重新扫码</el-tag>
        </template>

        <div class="fnwg-kv">
          <span class="fnwg-kv-key">所属连接</span>
          <span class="fnwg-kv-val">{{ row.interface_name }}</span>
        </div>
        <div class="fnwg-kv">
          <span class="fnwg-kv-key">允许访问</span>
          <span class="fnwg-kv-val">{{ describeAllowed(row.allowed_ips) }}</span>
        </div>
        <div class="fnwg-kv">
          <span class="fnwg-kv-key">最近通信</span>
          <span class="fnwg-kv-val">{{ timeAgo(row.last_handshake) }}</span>
        </div>
        <div class="fnwg-kv">
          <span class="fnwg-kv-key">累计流量</span>
          <span class="fnwg-kv-val">↓ {{ formatBytes(row.rx_bytes) }}　↑ {{ formatBytes(row.tx_bytes) }}</span>
        </div>
        <div class="fnwg-kv">
          <span class="fnwg-kv-key">有效期</span>
          <span class="fnwg-kv-val">{{ row.expire_at ? `剩 ${daysLeft(row.expire_at)} 天` : '长期有效' }}</span>
        </div>

        <template #actions>
          <el-button size="small" type="primary" @click="showConfig(row)">扫码连接</el-button>
          <el-button v-if="session.can('peer.write')" size="small" @click="openEdit(row)">编辑</el-button>
          <el-button v-if="session.can('peer.write')" size="small" @click="remove(row)">删除</el-button>
        </template>
      </ItemCard>
      <div v-if="!filtered.length && !loading" class="fnwg-empty">还没有设备，点击上方「添加设备」开始</div>
    </div>

    <!-- 添加 / 编辑设备：新建走分步向导（选用途 → 填信息 → 扫码），编辑仍是整页表单 -->
    <el-drawer
      v-model="drawerVisible"
      :title="form.id ? '编辑设备' : '添加设备'"
      :size="drawerSize"
      @closed="onDrawerClosed"
    >
      <el-steps v-if="!form.id" :active="createStep" simple style="margin-bottom: 16px">
        <el-step title="选择用途" />
        <el-step title="填写信息" />
        <el-step title="扫码连接" />
      </el-steps>

      <!-- 向导最后一步：创建完成，直接在本抽屉里扫码，不再跳到另一个弹窗 -->
      <div v-if="!form.id && createStep === 2">
        <el-alert
          v-if="cfg?.warning"
          type="warning"
          :closable="false"
          show-icon
          :title="cfg.warning"
          style="margin-bottom: 12px"
        />
        <div class="fnwg-steps">
          <span>1. 手机应用商店安装 <strong>WireGuard</strong> 官方 App</span>
          <span>2. 打开 App 点击「+」→「扫描二维码」</span>
          <span>3. 扫下方二维码，完成后打开开关即可连回家</span>
        </div>
        <div class="fnwg-qr">
          <img v-if="qrDataUrl" :src="qrDataUrl" alt="连接二维码" />
          <div style="font-size: 12px; opacity: 0.7; text-align: center; line-height: 1.7">
            连接地址：{{ cfg?.endpoint || '未配置（请到系统设置填写对外访问地址）' }}<br />
            分配给本设备的内部地址：{{ (cfg?.client_address || []).join(', ') || '-' }}
          </div>
        </div>
        <div style="display: flex; gap: 8px; justify-content: center; margin-top: 12px">
          <el-button @click="copy(cfg?.conf || '')">复制配置内容</el-button>
          <el-button @click="downloadConf">下载配置文件</el-button>
        </div>
      </div>

      <el-form
        v-show="form.id || createStep < 2"
        :model="form"
        class="fnwg-form"
        :label-position="isMobile ? 'top' : 'right'"
        label-width="130px"
      >
        <ScenarioPicker
          v-if="!form.id && createStep === 0"
          v-model="scenario"
          :presets="peerPresets"
          title="这台设备要怎么用？"
          @apply="applyScenario"
        />

        <template v-if="form.id || createStep === 1">
        <el-form-item>
          <template #label><FieldLabel :meta="P.name" /></template>
          <el-input v-model="form.name" placeholder="例如：妈妈的手机" />
          <FieldTips :meta="P.name" example />
        </el-form-item>

        <el-form-item v-if="interfaces.length > 1">
          <template #label><FieldLabel :meta="P.interface_id" /></template>
          <el-select v-model="form.interface_id" style="width: 100%">
            <el-option v-for="it in interfaces" :key="it.id" :label="it.name" :value="it.id" />
          </el-select>
          <FieldTips :meta="P.interface_id" />
        </el-form-item>

        <el-form-item>
          <template #label><FieldLabel :meta="P.route_mode" /></template>
          <el-radio-group v-model="form.route_mode">
            <el-radio v-for="o in routeModeOptions" :key="o.value" :value="o.value" class="fnwg-radio-line">
              {{ o.label }}
              <span class="fnwg-radio-desc">{{ o.desc }}</span>
            </el-radio>
          </el-radio-group>
          <FieldTips :meta="P.route_mode" example />
        </el-form-item>

        <el-form-item v-if="form.route_mode === 'custom'">
          <template #label>自定义可访问范围</template>
          <el-select
            v-model="form.client_allowed_ips"
            multiple
            filterable
            allow-create
            default-first-option
            placeholder="例如 192.168.2.0/24，输入后回车"
            style="width: 100%"
          >
            <!-- 探测到的家里网段直接列出来点选：手写 IP 段是最容易填错的一步 -->
            <el-option v-for="c in homeSubnets" :key="c" :label="c" :value="c" />
          </el-select>
          <div class="fnwg-hint">
            列出这台设备需要访问的网段；只有这些网段的流量会走本连接，其它上网流量不受影响。
            <template v-if="homeSubnets.length">
              已探测到家里网段：{{ homeSubnets.join('、') }}，点一下即可加入。
            </template>
          </div>
          <div v-if="form.id" class="fnwg-hint">
            提醒：通行范围写在设备配置里，保存后这台设备会显示「需重新扫码」，需要重新导入一次才会生效。
          </div>
        </el-form-item>

        <el-form-item>
          <template #label><FieldLabel :meta="P.allowed_ips" /></template>
          <el-select
            v-model="form.allowed_ips"
            multiple
            filterable
            allow-create
            default-first-option
            placeholder="留空即自动分配（推荐）"
            style="width: 100%"
          />
          <FieldTips :meta="P.allowed_ips" example />
        </el-form-item>

        <el-form-item v-if="!form.id">
          <template #label><FieldLabel :meta="P.generate_keys" /></template>
          <el-switch v-model="form.generate_keys" active-text="自动生成" />
          <div style="margin-top: 6px">
            <el-switch v-model="form.generate_psk" />
            <span style="margin-left: 6px; font-size: 13px">
              <FieldLabel :meta="P.generate_psk" />
            </span>
          </div>
        </el-form-item>

        <template v-else>
          <el-form-item>
            <template #label><FieldLabel :meta="P.public_key" /></template>
            <el-input v-model="form.public_key" class="fnwg-mono" />
            <FieldTips :meta="P.public_key" />
          </el-form-item>
          <el-form-item label="更换密钥">
            <el-switch v-model="form.generate_keys" active-text="保存时生成新的密钥对" />
            <el-switch v-model="form.generate_psk" active-text="生成新口令" style="margin-left: 12px" />
          </el-form-item>
        </template>

        <el-form-item>
          <template #label><FieldLabel :meta="P.persistent_keepalive" /></template>
          <el-input-number v-model="form.persistent_keepalive" :min="0" :max="3600" :step="5" />
          <FieldTips :meta="P.persistent_keepalive" example />
        </el-form-item>

        <el-collapse style="margin-top: 8px">
          <el-collapse-item title="更多设置（可选）" name="more">
            <el-form-item>
              <template #label><FieldLabel :meta="P.group_tag" /></template>
              <el-input v-model="form.group_tag" placeholder="例如：家人设备" />
              <FieldTips :meta="P.group_tag" example />
            </el-form-item>
            <el-form-item>
              <template #label><FieldLabel :meta="P.remark" /></template>
              <el-input v-model="form.remark" placeholder="例如：2026-09 发放" />
              <FieldTips :meta="P.remark" />
            </el-form-item>
            <el-form-item>
              <template #label><FieldLabel :meta="P.expire_at" /></template>
              <el-date-picker
                v-model="form.expire_at"
                type="datetime"
                placeholder="留空表示长期有效"
                style="width: 100%"
              />
              <FieldTips :meta="P.expire_at" example />
            </el-form-item>
            <el-form-item>
              <template #label><FieldLabel :meta="P.quota_rx" /></template>
              <el-input-number v-model="form.quota_rx" :min="0" :step="1073741824" controls-position="right" />
              <FieldTips :meta="P.quota_rx" example />
            </el-form-item>
            <el-form-item>
              <template #label><FieldLabel :meta="P.endpoint_host" /></template>
              <el-input v-model="form.endpoint_host" placeholder="一般留空" />
              <FieldTips :meta="P.endpoint_host" example />
            </el-form-item>
            <el-form-item v-if="form.endpoint_host">
              <template #label><FieldLabel :meta="P.endpoint_port" /></template>
              <el-input-number v-model="form.endpoint_port" :min="0" :max="65535" />
              <FieldTips :meta="P.endpoint_port" example />
            </el-form-item>
          </el-collapse-item>
        </el-collapse>

        <el-form-item>
          <template #label><FieldLabel :meta="P.enabled" /></template>
          <el-switch v-model="form.enabled" active-text="允许这台设备连接" />
          <FieldTips :meta="P.enabled" />
        </el-form-item>
        </template>
      </el-form>

      <template #footer>
        <div style="display: flex; gap: 8px; justify-content: flex-end; width: 100%">
          <!-- 编辑：单一保存按钮 -->
          <template v-if="form.id">
            <el-button @click="drawerVisible = false">取消</el-button>
            <el-button type="primary" :loading="saving" @click="submit">保存</el-button>
          </template>
          <!-- 新建向导：按步骤推进 -->
          <template v-else-if="createStep === 0">
            <el-button @click="drawerVisible = false">取消</el-button>
            <el-button type="primary" @click="createStep = 1">下一步</el-button>
          </template>
          <template v-else-if="createStep === 1">
            <el-button @click="createStep = 0">上一步</el-button>
            <el-button type="primary" :loading="saving" @click="submit">创建并生成二维码</el-button>
          </template>
          <template v-else>
            <el-button type="primary" @click="drawerVisible = false">完成</el-button>
          </template>
        </div>
      </template>
    </el-drawer>

    <!-- 扫码连接 -->
    <el-dialog v-model="cfgVisible" title="用手机扫码连接" :width="dialogWidth || '680px'">
      <el-alert v-if="cfg?.warning" type="warning" :closable="false" show-icon :title="cfg.warning" style="margin-bottom: 12px" />
      <div class="fnwg-steps">
        <span>1. 手机应用商店安装 <strong>WireGuard</strong> 官方 App</span>
        <span>2. 打开 App 点击「+」→「扫描二维码」</span>
        <span>3. 扫下方二维码，完成后打开开关即可连回家</span>
      </div>

      <el-tabs>
        <el-tab-pane label="二维码（推荐）">
          <div class="fnwg-qr">
            <img v-if="qrDataUrl" :src="qrDataUrl" alt="连接二维码" />
            <div style="font-size: 12px; opacity: 0.7; text-align: center; line-height: 1.7">
              连接地址：{{ cfg?.endpoint || '未配置（请到系统设置填写对外访问地址）' }}<br />
              分配给本设备的内部地址：{{ (cfg?.client_address || []).join(', ') || '-' }}
            </div>
          </div>
        </el-tab-pane>
        <el-tab-pane label="配置文件（手动导入）">
          <div class="fnwg-pre">{{ cfg?.conf }}</div>
        </el-tab-pane>
      </el-tabs>

      <template #footer>
        <el-button @click="copy(cfg?.conf || '')">复制配置内容</el-button>
        <el-button type="primary" @click="downloadConf">下载配置文件</el-button>
        <el-button @click="cfgVisible = false">关闭</el-button>
      </template>
    </el-dialog>

    <!-- 批量导入设备 -->
    <el-dialog v-model="importVisible" title="批量添加设备" :width="dialogWidth || '760px'">
      <el-alert type="info" :closable="false" show-icon style="margin-bottom: 12px">
        <template #title>
          每行一台设备，用「逗号」或「制表符」分隔：<code>名称,识别码,备注,分组</code>。识别码可留空（留空会自动生成密钥并托管）。
        </template>
      </el-alert>

      <el-form label-width="90px" :label-position="isMobile ? 'top' : 'right'">
        <el-form-item label="导入到">
          <el-select v-model="importIface" style="width: 100%">
            <el-option v-for="it in interfaces" :key="it.id" :label="it.name" :value="it.id" />
          </el-select>
        </el-form-item>
        <el-form-item label="设备清单">
          <el-input
            v-model="importText"
            type="textarea"
            :rows="7"
            :placeholder="importPlaceholder"
          />
        </el-form-item>
      </el-form>

      <div v-if="importRows.length" class="fnwg-hint" style="margin-bottom: 8px">
        共解析出 {{ importRows.length }} 行，将导入 {{ importReady.length }} 台<template v-if="importRows.length - importReady.length">
          （跳过 {{ importRows.length - importReady.length }} 行空名称）</template
        >。
      </div>
      <el-table v-if="importRows.length" :data="importRows.slice(0, 50)" size="small" max-height="220">
        <el-table-column type="index" label="#" width="50" />
        <el-table-column prop="name" label="名称" min-width="120" />
        <el-table-column label="识别码" min-width="200">
          <template #default="{ row }">
            <span v-if="!row.public_key" class="fnwg-hint">留空，自动生成</span>
            <span v-else-if="row.public_key.length !== 44" class="fnwg-warn">长度 {{ row.public_key.length }}，应为 44 位</span>
            <span v-else class="fnwg-mono">{{ row.public_key.slice(0, 14) }}…</span>
          </template>
        </el-table-column>
        <el-table-column prop="group_tag" label="分组" width="90" />
        <el-table-column prop="remark" label="备注" width="110" />
      </el-table>
      <div v-if="importRows.length > 50" class="fnwg-hint">预览只显示前 50 行，实际会全部导入。</div>

      <div v-if="importResult" style="margin-top: 12px">
        <el-alert
          :type="importResult.failed ? 'warning' : 'success'"
          :closable="false"
          show-icon
          :title="`导入完成：成功 ${importResult.created} 台${importResult.failed ? `，失败 ${importResult.failed} 台` : ''}`"
        />
        <div v-if="importResult.failed" style="margin-top: 8px">
          <el-button size="small" @click="copyFailures">复制失败清单</el-button>
          <el-table
            :data="importResult.items.filter((i) => !i.ok)"
            size="small"
            max-height="200"
            style="margin-top: 8px"
          >
            <el-table-column prop="name" label="名称" width="140" />
            <el-table-column prop="error" label="失败原因" min-width="260" />
          </el-table>
        </div>
      </div>

      <template #footer>
        <el-button @click="importVisible = false">关闭</el-button>
        <el-button type="primary" :loading="importing" :disabled="!importReady.length" @click="submitImport">
          开始导入（{{ importReady.length }}）
        </el-button>
      </template>
    </el-dialog>

    <ConfigHelpDrawer v-model="helpVisible" :groups="helpGroups" />
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus, Refresh, ArrowDown, Reading, Upload } from '@element-plus/icons-vue'
import QRCode from 'qrcode'
import { api } from '@/api/client'
import type {
  PeerConfigResult,
  PeerImportResult,
  PeerImportRow,
  TrafficReport,
  WgInterface,
  WgPeer,
} from '@/api/types'
import ConfigHelpDrawer from '@/components/ConfigHelpDrawer.vue'
import FieldLabel from '@/components/FieldLabel.vue'
import FieldTips from '@/components/FieldTips.vue'
import ItemCard from '@/components/ItemCard.vue'
import ScenarioPicker from '@/components/ScenarioPicker.vue'
import {
  allHelpGroups,
  interfaceFields,
  peerFields,
  peerPresets,
  routeModeOptions,
} from '@/constants/fields'
import { useBreakpoint } from '@/composables/useBreakpoint'
import { useSystemHealth } from '@/composables/useSystemHealth'
import { useSession } from '@/stores/session'
import { daysLeft, formatBytes, handshakeLevel, timeAgo } from '@/utils/format'
import { copyText } from '@/utils/clipboard'

const route = useRoute()
const session = useSession()
const { isMobile, drawerSize, dialogWidth } = useBreakpoint()

// 复用全局已拉取的自检结果：只为了拿到探测到的家里网段，
// 让「自定义可访问范围」可以直接点选，而不是凭记忆手写 IP。
const { net } = useSystemHealth()
const homeSubnets = computed(() => net.value?.home_subnets || [])

const P = peerFields
const helpGroups = allHelpGroups
void interfaceFields

const interfaces = ref<WgInterface[]>([])
const peers = ref<WgPeer[]>([])
const loading = ref(false)

/** 每台设备的本月发送量与额度，来自流量报表（见 loadUsage）。 */
const usage = ref<Record<number, { month_tx_bytes: number; quota_tx: number }>>({})
const saving = ref(false)
const selectedIds = ref<number[]>([])
const ifaceFilter = ref<number | undefined>(undefined)
const keyword = ref('')

const drawerVisible = ref(false)
const cfgVisible = ref(false)
const helpVisible = ref(false)
const cfg = ref<PeerConfigResult | null>(null)
const qrDataUrl = ref('')
const scenario = ref('split')
// 新建向导当前步骤：0 选用途 / 1 填信息 / 2 扫码
const createStep = ref(0)

// 批量导入
const importVisible = ref(false)
const importText = ref('')
const importIface = ref<number | undefined>(undefined)
const importing = ref(false)
const importResult = ref<PeerImportResult | null>(null)
const importPlaceholder = '妈妈的手机\n爸爸的手机\n客厅电视,<44 位识别码>,客厅,固定设备'

const emptyForm = () => ({
  id: 0,
  interface_id: undefined as number | undefined,
  name: '',
  public_key: '',
  generate_keys: true,
  generate_psk: true,
  route_mode: 'lan',
  client_allowed_ips: [] as string[],
  allowed_ips: [] as string[],
  endpoint_host: '',
  endpoint_port: 0,
  persistent_keepalive: 25,
  group_tag: '',
  remark: '',
  expire_at: null as string | null,
  quota_rx: 0,
  quota_tx: 0,
  enabled: true,
})
const form = reactive(emptyForm())

const filtered = computed(() => {
  const kw = keyword.value.trim().toLowerCase()
  if (!kw) return peers.value
  return peers.value.filter(
    (p) =>
      p.name.toLowerCase().includes(kw) ||
      p.remark.toLowerCase().includes(kw) ||
      p.group_tag.toLowerCase().includes(kw),
  )
})

const onlineCount = computed(
  () => filtered.value.filter((p) => handshakeLevel(p.last_handshake) !== 'off').length,
)

/** 解析批量导入文本：每行一台设备，逗号或制表符分隔，`#` 开头为注释。 */
function parseImportText(text: string): PeerImportRow[] {
  const out: PeerImportRow[] = []
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim()
    if (!line || line.startsWith('#')) continue
    const cols = line.split(/[,\t]/).map((s) => s.trim())
    out.push({
      name: cols[0] || '',
      public_key: cols[1] || '',
      remark: cols[2] || '',
      group_tag: cols[3] || '',
    })
  }
  return out
}

const importRows = computed(() => parseImportText(importText.value))
// 只有带名称的行才提交；没有名称的行无法标识，导入也没有意义
const importReady = computed(() => importRows.value.filter((r) => r.name.trim() !== ''))

/** 把技术化的 AllowedIPs 翻译成用户能理解的描述 */
function describeAllowed(ips?: string[]): string {
  if (!ips || !ips.length) return '未设置'
  if (ips.includes('0.0.0.0/0')) return '全部上网流量都走这里'
  const lan = ips.filter((i) => !i.endsWith('/32') && !i.endsWith('/128'))
  if (lan.length) return `可访问 ${lan.length} 个网段（含家庭内网）`
  return '仅本机内部地址'
}

function stateLabel(row: WgPeer): string {
  if (!row.enabled) return '已停用'
  const lv = handshakeLevel(row.last_handshake)
  if (lv === 'ok') return '在线'
  if (lv === 'warn') return '刚刚在线'
  return '离线'
}

function stateTagType(row: WgPeer): 'success' | 'warning' | 'info' {
  if (!row.enabled) return 'info'
  const lv = handshakeLevel(row.last_handshake)
  if (lv === 'ok') return 'success'
  if (lv === 'warn') return 'warning'
  return 'info'
}

async function loadInterfaces() {
  const data = await api.get<{ items: WgInterface[] }>('/interfaces')
  interfaces.value = data.items || []
  if (!form.interface_id && interfaces.value.length) form.interface_id = interfaces.value[0].id
}

async function load() {
  loading.value = true
  try {
    const q = ifaceFilter.value ? `?interface_id=${ifaceFilter.value}` : ''
    const data = await api.get<{ items: WgPeer[] }>(`/peers${q}`)
    peers.value = data.items || []
    selectedIds.value = []
  } catch (e) {
    ElMessage.error((e as Error).message)
  } finally {
    loading.value = false
  }
  // 用量单独取一次（设备列表接口不带它，而它来自按小时的记账明细）。
  // 放在 load 的末尾：设备的新增、删除、改额度都会经过 load，
  // 于是「本月用量」自动跟着刷新，不必在每个操作里各记一次。
  void loadUsage()
}

/**
 * 取每台设备的本月发送量与额度。
 *
 * 报表接口的区间参数给 1 天：这里只要「本月」这一个数（它按自然月单独累计，
 * 与区间无关），逐日明细不必带回来。
 */
async function loadUsage() {
  try {
    const rep = await api.get<TrafficReport>('/traffic/report?days=1')
    const map: Record<number, { month_tx_bytes: number; quota_tx: number }> = {}
    for (const p of rep.peers || []) {
      map[p.peer_id] = { month_tx_bytes: p.month_tx_bytes, quota_tx: p.quota_tx }
    }
    usage.value = map
  } catch {
    // 用量取不到不该影响设备管理：这一列留空即可，删掉设备、改配置照样能做
    usage.value = {}
  }
}

/** 本月用量占额度的百分比（没有额度时返回 0，不显示进度条）。 */
function usagePercent(id: number) {
  const u = usage.value[id]
  if (!u || !u.quota_tx) return 0
  return Math.min(100, Math.round((u.month_tx_bytes / u.quota_tx) * 100))
}

/** 是否已经用满额度 —— 用满就会触发自动停用，这一列必须能一眼看出来。 */
function overQuota(id: number) {
  const u = usage.value[id]
  return !!u && u.quota_tx > 0 && u.month_tx_bytes >= u.quota_tx
}

function onSelectionChange(rows: WgPeer[]) {
  selectedIds.value = rows.map((r) => r.id)
}

function toggleSelect(id: number) {
  const i = selectedIds.value.indexOf(id)
  if (i >= 0) selectedIds.value.splice(i, 1)
  else selectedIds.value.push(id)
}

function selectAll() {
  selectedIds.value =
    selectedIds.value.length === filtered.value.length ? [] : filtered.value.map((p) => p.id)
}

function openCreate() {
  if (!interfaces.value.length) {
    ElMessage.warning('请先创建一条连接，再添加设备')
    return
  }
  Object.assign(form, emptyForm())
  form.interface_id = ifaceFilter.value || interfaces.value[0].id
  scenario.value = 'split'
  createStep.value = 0
  drawerVisible.value = true
}

/** 关闭抽屉时复位向导步骤，下次打开从第一步开始 */
function onDrawerClosed() {
  createStep.value = 0
}

function openEdit(row: WgPeer) {
  Object.assign(form, {
    id: row.id,
    interface_id: row.interface_id,
    name: row.name,
    public_key: row.public_key,
    generate_keys: false,
    generate_psk: false,
    route_mode: row.route_mode || 'lan',
    client_allowed_ips: [...(row.client_allowed_ips || [])],
    allowed_ips: [...(row.allowed_ips || [])],
    endpoint_host: row.endpoint_host,
    endpoint_port: row.endpoint_port,
    persistent_keepalive: row.persistent_keepalive,
    group_tag: row.group_tag,
    remark: row.remark,
    expire_at: row.expire_at || null,
    quota_rx: row.quota_rx,
    quota_tx: row.quota_tx,
    enabled: row.enabled,
  })
  drawerVisible.value = true
}

function applyScenario(values: Record<string, unknown>) {
  Object.assign(form, values)
}

async function submit() {
  saving.value = true
  try {
    const payload = {
      interface_id: form.interface_id,
      name: form.name,
      public_key: form.public_key,
      generate_keys: form.generate_keys,
      generate_psk: form.generate_psk,
      route_mode: form.route_mode,
      client_allowed_ips: form.client_allowed_ips,
      auto_address: true,
      allowed_ips: form.allowed_ips,
      endpoint_host: form.endpoint_host,
      endpoint_port: form.endpoint_port,
      persistent_keepalive: form.persistent_keepalive,
      group_tag: form.group_tag,
      remark: form.remark,
      expire_at: form.expire_at || null,
      quota_rx: form.quota_rx,
      quota_tx: form.quota_tx,
      enabled: form.enabled,
    }
    if (form.id) {
      await api.patch(`/peers/${form.id}`, payload)
      ElMessage.success('已保存')
      drawerVisible.value = false
      await load()
      return
    }
    const created = await api.post<WgPeer>('/peers', payload)
    ElMessage.success('设备已添加')
    await load()
    // 向导最后一步：在本抽屉里直接展示二维码，用户不必再点一次「扫码连接」
    await loadConfig(created)
    createStep.value = 2
  } catch (e) {
    ElMessage.error((e as Error).message)
  } finally {
    saving.value = false
  }
}

/** 拉取并渲染某台设备的二维码/配置（不打开弹窗），供向导与扫码弹窗共用。 */
async function loadConfig(row: WgPeer) {
  const res = await api.get<PeerConfigResult>(`/peers/${row.id}/config`)
  cfg.value = res
  qrDataUrl.value = await QRCode.toDataURL(res.qr_payload || res.conf, { margin: 1, width: 480 })
  // 生成配置等于把最新设置交付给了设备，服务端已记下这次交付；
  // 立刻刷新列表，让「需重新扫码」标记当场消失（否则要等下次手动刷新）。
  if (row.config_stale) await load()
}

async function showConfig(row: WgPeer) {
  try {
    await loadConfig(row)
    cfgVisible.value = true
  } catch (e) {
    ElMessage.error((e as Error).message)
  }
}

function openImport() {
  if (!interfaces.value.length) {
    ElMessage.warning('请先创建一条连接，再批量导入设备')
    return
  }
  importText.value = ''
  importResult.value = null
  importIface.value = ifaceFilter.value || interfaces.value[0].id
  importVisible.value = true
}

async function submitImport() {
  const devices = importReady.value
  if (!devices.length) return
  importing.value = true
  try {
    const res = await api.post<PeerImportResult>('/peers/import', {
      interface_id: importIface.value,
      devices,
    })
    importResult.value = res
    if (res.failed) ElMessage.warning(`成功 ${res.created} 台，失败 ${res.failed} 台`)
    else ElMessage.success(`已创建 ${res.created} 台设备`)
    await load()
  } catch (e) {
    ElMessage.error((e as Error).message)
  } finally {
    importing.value = false
  }
}

/** 把失败清单复制成「名称 + 原因」两列文本，方便用户回去改源头数据 */
async function copyFailures() {
  const items = (importResult.value?.items || []).filter((i) => !i.ok)
  await copy(items.map((i) => `${i.name}\t${i.error}`).join('\n'))
}

function downloadConf() {
  if (!cfg.value) return
  const blob = new Blob([cfg.value.conf], { type: 'text/plain;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = cfg.value.filename
  a.click()
  URL.revokeObjectURL(url)
}

async function remove(row: WgPeer) {
  try {
    await ElMessageBox.confirm(
      `确认删除设备「${row.name}」？删除后该设备将无法连接，且需要重新扫码才能恢复。\n如果只是临时收回权限，建议改为「停用」。`,
      '删除设备',
      { type: 'warning' },
    )
    await api.del(`/peers/${row.id}`)
    ElMessage.success('已删除')
    await load()
  } catch (e) {
    if (e !== 'cancel') ElMessage.error((e as Error).message)
  }
}

async function batch(action: string) {
  const ids = [...selectedIds.value]
  if (!ids.length) return
  const payload: Record<string, unknown> = { ids, action }
  try {
    if (action === 'delete') {
      await ElMessageBox.confirm(
        `确认永久删除选中的 ${ids.length} 台设备？此操作无法撤销。`,
        '批量删除',
        { type: 'warning' },
      )
    } else if (action === 'keepalive') {
      const { value } = await ElMessageBox.prompt(
        '每隔多少秒发送一次心跳，保持设备在线（推荐 25 秒）',
        '统一设置心跳间隔',
        { inputValue: '25', inputPattern: /^\d+$/, inputErrorMessage: '请输入数字' },
      )
      payload.persistent_keepalive = Number(value)
    } else if (action === 'group') {
      const { value } = await ElMessageBox.prompt('给这些设备打一个分类标签', '统一设置分组标签', {
        inputValue: '默认分组',
      })
      payload.group_tag = value
    } else if (action === 'extend') {
      const { value } = await ElMessageBox.prompt('从今天（或原到期日）起再延长多少天', '统一延长使用期限', {
        inputValue: '30',
        inputPattern: /^\d+$/,
        inputErrorMessage: '请输入数字',
      })
      payload.extend_days = Number(value)
    } else if (action === 'quota') {
      const { value } = await ElMessageBox.prompt(
        '每台设备的流量上限（字节）。1073741824 约等于 1 GB，填 0 表示不限制',
        '统一设置流量上限',
        { inputValue: '0', inputPattern: /^\d+$/, inputErrorMessage: '请输入数字' },
      )
      payload.quota_rx = Number(value)
      payload.quota_tx = Number(value)
    }
    const res = await api.post<{ message: string }>('/peers/batch', payload)
    ElMessage.success(res.message)
    await load()
  } catch (e) {
    if (e !== 'cancel') ElMessage.error((e as Error).message)
  }
}

async function copy(text: string) {
  // 局域网 http 访问下 navigator.clipboard 不存在，走 copyText 的退路（见 utils/clipboard.ts）
  if (await copyText(text)) {
    ElMessage.success('已复制')
    return
  }
  ElMessage.warning('当前访问方式下浏览器不允许自动复制，请手动选择复制')
}

onMounted(async () => {
  const q = route.query
  if (q.iface) ifaceFilter.value = Number(q.iface)
  await loadInterfaces()
  await load()
  // 从全局搜索跳过来时自动打开目标设备
  if (q.edit) {
    const target = peers.value.find((p) => p.id === Number(q.edit))
    if (target) openEdit(target)
  }
})

// 页面已挂载时再次从搜索跳过来（query 变化不会再触发 onMounted），需要单独监听
watch(
  () => route.query,
  async (q) => {
    if (q.iface && Number(q.iface) !== ifaceFilter.value) {
      ifaceFilter.value = Number(q.iface)
      await load()
    }
    if (q.edit) {
      const target = peers.value.find((p) => p.id === Number(q.edit))
      if (target) openEdit(target)
    }
  },
)
</script>

<style scoped>
.fnwg-steps {
  display: flex;
  flex-direction: column;
  gap: 4px;
  font-size: 12.5px;
  color: var(--el-text-color-regular);
  line-height: 1.7;
  margin-bottom: 12px;
  padding: 10px 12px;
  border-radius: 8px;
  background: var(--el-fill-color-light);
}

/* 批量导入预览里的「识别码长度不对」提示 */
.fnwg-warn {
  color: var(--el-color-warning);
  font-size: 12px;
}

/* 本月用量已经触到额度上限：用满就会被自动停用，这一眼必须看得出来 */
.fnwg-over-quota {
  color: var(--el-color-danger);
}
</style>
