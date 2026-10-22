<script setup lang="ts">
import { computed, ref, onUnmounted } from 'vue'
import Icon from './Icon.vue'
import { api, ApiError, setCredential, type Asset, type Detail, type Group } from './api'
const loggedIn = ref(false), token = ref(''), busy = ref(false), error = ref(''), notice = ref('')
const page = ref('assets'), assets = ref<Asset[]>([]), groups = ref<Group[]>([]), detail = ref<Detail | null>(null)
const group = ref(''), search = ref(''), cursor = ref<string | null>(null), next = ref<string | null>(null), fetchedAt = ref('')
const tab = ref('overview'), hideLoopback = ref(false), tableSearch = ref(''), groupName = ref('')
const editGroup = ref(''), editName = ref(''), editTags = ref(''), editing = ref(false)
const pageSize = 100
let requestGeneration = 0
const domainNames: Record<string,string> = {host:'主机信息',cpu:'CPU 速率',memory:'内存',network:'网卡',processes:'进程',ports:'端口',packages:'软件包',fingerprint:'机器指纹',network_rates:'网卡速率',architecture:'主机架构'}
const statusNames: Record<string,string> = {complete:'已采集',partial:'部分采集',unavailable:'未知 / 不可用',unsupported:'未支持',fresh:'近期采集',stale:'已过期',unknown:'等待采集'}
const title = computed(() => detail.value ? detail.value.asset.display_name : page.value === 'groups' ? '主机分组' : page.value === 'capabilities' ? '能力与覆盖边界' : '主机资产')
const freshCount = computed(() => assets.value.filter(a=>a.freshness==='fresh').length)
const knownCpu = computed(() => assets.value.filter(a=>a.metrics?.cpu_percent != null))
const averageCpu = computed(()=> knownCpu.value.length ? (knownCpu.value.reduce((sum,a)=>sum+(a.metrics?.cpu_percent ?? 0),0)/knownCpu.value.length).toFixed(1)+'%' : '未知')
const coverage = computed(()=>detail.value?.collections.find(c=>c.kind==='inventory')?.latest_attempt.coverage ?? detail.value?.asset.metrics?.quality ?? {})
const filteredPackages = computed(()=>detail.value?.packages.filter(p=>(p.name+' '+p.version).toLowerCase().includes(tableSearch.value.toLowerCase())) ?? [])
const filteredProcesses = computed(()=>detail.value?.processes.filter(p=>(p.pid+' '+p.name).toLowerCase().includes(tableSearch.value.toLowerCase())) ?? [])
const shownPorts = computed(()=>detail.value?.ports.filter(p=>!hideLoopback.value || !p.loopback) ?? [])
function coverageReason(reason: string) {
  if(reason.startsWith('limit_exceeded'))return '达到采集或传输预算，只保留部分清单。'
  const labels:Record<string,string>={first_sample_reset_or_missing_boot_identity:'首次采样、计数器重置或启动标识不可用；等待下一次有效采样。',first_sample_counter_reset_or_interface_identity_changed:'首次采样、计数器重置或网卡标识改变，速率暂不可确认。',machine_id_missing_or_invalid:'机器标识缺失或格式不正确，无法生成派生指纹。',partial_source_coverage:'部分数据源无法完整读取，请核对宿主挂载与采集权限。',source_missing:'所需宿主数据源缺失，请核对只读挂载。',source_read_or_parse_error:'数据源读取或解析失败，保留未知状态。',source_permission_denied:'没有读取宿主数据源的权限。',source_not_applicable:'当前数据源不适用或采集器未启用。',interface_identity_missing:'网卡标识不可读取，无法确认连续样本属于同一接口。',host_architecture_not_observed:'尚未从宿主软件包数据库确认架构。'}
  return labels[reason] ?? reason
}
function date(value: string | null | undefined) { return value ? new Date(value).toLocaleString('zh-CN',{hour12:false}) : '尚无数据' }
function bytes(value: number | null | undefined) { if(value == null) return '未知'; if(value === 0) return '0 B'; const i=Math.min(Math.floor(Math.log(value)/Math.log(1024)),4); return `${(value/1024**i).toFixed(i?1:0)} ${['B','KiB','MiB','GiB','TiB'][i]}` }
function percent(value: number | null | undefined) { return value == null ? '未知' : value.toFixed(1)+'%' }
function memory(asset: Asset) { const m=asset.metrics; return m?.memory_total_bytes && m.memory_available_bytes != null ? 100*(m.memory_total_bytes-m.memory_available_bytes)/m.memory_total_bytes : null }
function describe(err: unknown) {
  if(err instanceof ApiError) {
    if(err.status===401 || err.status===403) { loggedIn.value=false; setCredential(''); token.value=''; return '凭证无效或管理员权限已停用，请重新登录。' }
    const messages: Record<string,string>={constraint_conflict:'数据冲突：名称可能已存在，或关联状态已改变。',group_not_found:'分组不存在或已删除。',invalid_request:'输入格式不正确，请检查后重试。',database_unavailable:'数据库暂时不可用，请稍后重试。'}
    return messages[err.code] ?? `请求失败（${err.status} / ${err.code}）`
  }
  return '连接失败或请求超时，请检查 Hub 是否运行。'
}
async function work(fn:()=>Promise<void>) {busy.value=true;error.value='';notice.value='';try{await fn()}catch(e){error.value=describe(e)}finally{busy.value=false}}
async function load() {
  const generation=++requestGeneration
  const params=new URLSearchParams({limit:String(pageSize)})
  if(group.value)params.set('group_id',group.value)
  if(search.value.trim())params.set('q',search.value.trim())
  if(cursor.value)params.set('after',cursor.value)
  const [list,g]=await Promise.all([api<{items:Asset[];next_cursor:string|null}>('/assets?'+params),api<{items:Group[]}>('/groups')])
  if(generation!==requestGeneration || !loggedIn.value)return
  assets.value=list.items;next.value=list.next_cursor;groups.value=g.items;fetchedAt.value=new Date().toISOString()
}
async function login() { await work(async()=>{ setCredential(token.value);await api('/session');token.value='';loggedIn.value=true;await load() }) }
function logout(){loggedIn.value=false;setCredential('');token.value='';assets.value=[];groups.value=[];detail.value=null;error.value='';requestGeneration++}
async function refresh(){await work(async()=>{if(detail.value){await openDetail(detail.value.asset.id)}else{await load()}})}
async function openDetail(id:string){ const generation=++requestGeneration; const d=await api<Detail>('/assets/'+id);if(generation!==requestGeneration || !loggedIn.value)return false;detail.value=d;editGroup.value=d.asset.group_id;editName.value=d.asset.display_name;editTags.value=Object.entries(d.asset.tags).map(([k,v])=>k+'='+v).join('\n');fetchedAt.value=new Date().toISOString();return true }
async function selectAsset(id:string){tab.value='overview';tableSearch.value='';editing.value=false;await work(async()=>{await openDetail(id)})}
function navigate(value:string){requestGeneration++;page.value=value;detail.value=null;editing.value=false;error.value=''}
async function filter(){cursor.value=null;await work(load)}
async function more(){cursor.value=next.value;await work(load)}
async function createGroup(){await work(async()=>{await api('/groups',{method:'POST',body:JSON.stringify({name:groupName.value.trim()})});groupName.value='';await load();notice.value='分组已创建。'})}
async function saveAsset(){await work(async()=>{
  if(!detail.value)return
  const assetId=detail.value.asset.id, generation=++requestGeneration
  const tags:Record<string,string>={};for(const line of editTags.value.split('\n').filter(l=>l.trim())){const i=line.indexOf('=');if(i<1)throw new ApiError(400,'invalid_request');tags[line.slice(0,i).trim()]=line.slice(i+1).trim()}
  await api('/assets/'+assetId,{method:'PATCH',body:JSON.stringify({display_name:editName.value,group_id:editGroup.value,tags})})
  if(generation!==requestGeneration || !loggedIn.value)return
  if(await openDetail(assetId)){editing.value=false;notice.value='资产分组与标签已保存。'}
})}
const refreshTimer=setInterval(()=>{if(loggedIn.value&&!busy.value&&!editing.value)void refresh()},30000)
onUnmounted(()=>clearInterval(refreshTimer))
</script>
<template>
  <div v-if="!loggedIn" class="login-screen">
    <section class="login-brand"><div class="brand large"><span class="brand-mark"><Icon name="shield"/></span>Sentinel<span class="edition">HUB</span></div><h1>看见主机的<br>真实状态。</h1><p>资产、运行指标与采集覆盖，<br>从一个清晰的视图开始。</p><div class="login-note"><Icon name="shield"/><span>一期 A · 只读主机观测</span></div></section>
    <section class="login-form"><span class="eyebrow">HOST SECURITY CONSOLE</span><h2>连接管理控制台</h2><p class="muted">输入此 Hub 的管理员凭证。</p><form @submit.prevent="login"><label for="credential">管理员凭证</label><div class="input-icon"><Icon name="lock"/><input id="credential" v-model="token" type="password" required minlength="32" autocomplete="off" placeholder="输入管理员令牌"/></div><p v-if="error" role="alert" class="error">{{error}}</p><button class="primary full" :disabled="busy || token.length<32">{{busy?'正在连接…':'进入控制台'}} <span>→</span></button></form><p class="login-boundary">开发模式 · 单管理员授权<br>凭证只保留在本次页面内存中。跨主机使用前请配置 HTTPS。</p></section>
  </div>
  <template v-else>
    <a class="skip" href="#main">跳转到内容</a>
    <aside class="sidebar"><a href="#" class="brand" @click.prevent="navigate('assets')"><span class="brand-mark"><Icon name="shield"/></span>Sentinel<span class="edition">HUB</span></a><div class="organization"><span class="org-icon">S</span><span>内部主机空间<small>开发环境</small></span></div><div class="nav-label">工作空间</div><nav><button :class="{active:page==='assets'}" @click="navigate('assets')"><Icon name="server"/>主机资产</button><button :class="{active:page==='groups'}" @click="navigate('groups')"><Icon name="layers"/>主机分组</button><button :class="{active:page==='capabilities'}" @click="navigate('capabilities')"><Icon name="activity"/>能力与覆盖</button></nav><div class="nav-label spaced">后续能力</div><div class="planned-nav"><span>漏洞与基线</span><small>未接入</small></div><div class="planned-nav"><span>程序升级</span><small>未接入</small></div><div class="planned-nav"><span>AI 诊断</span><small>未接入</small></div><div class="sidebar-bottom"><div class="readonly"><Icon name="shield"/>只读采集 · 无自动处置</div><button class="user" @click="logout"><span class="avatar">AD</span><span>管理员<small>开发凭证</small></span><Icon name="logout"/></button></div></aside>
    <div class="workspace"><header class="topbar"><span class="breadcrumb">Sentinel <span>/</span> 工作空间 <span>/</span> <strong>{{title}}</strong></span><div class="top-actions"><span class="dev-badge">DEVELOPMENT</span><button class="logout-button" aria-label="退出登录" title="退出登录" @click="logout"><Icon name="logout"/><span>退出</span></button></div></header>
      <main id="main" tabindex="-1"><div class="heading"><div><div class="eyebrow">{{detail?'HOST OBSERVATION':'INFRASTRUCTURE / ASSETS'}}</div><h1>{{title}}</h1><p>{{detail?'展示真实采集数据；未知字段不作安全结论。':'集中查看主机资产、运行状态和采集覆盖。'}}</p></div><button class="button" :disabled="busy" @click="refresh"><Icon name="refresh"/>{{busy?'加载中…':'刷新数据'}}</button></div>
        <p v-if="error" class="error banner" role="alert"><Icon name="alert"/>{{error}} <button @click="refresh">重试</button></p><p v-if="notice" class="success banner" role="status">{{notice}}</p>
        <template v-if="detail">
          <button class="back" @click="navigate('assets')"><Icon name="arrow"/>返回主机资产</button>
          <div class="asset-hero panel"><div class="host-icon"><Icon name="server"/></div><div><h2>{{detail.asset.hostname ?? detail.asset.display_name}}</h2><p class="muted mono">{{detail.asset.id}}</p><div class="tag-row"><span class="badge">{{detail.asset.group_name}}</span><span v-for="(value,key) in detail.asset.tags" :key="key" class="tag">{{key}}={{value}}</span></div></div><div class="hero-status"><span class="status" :class="detail.asset.freshness">{{statusNames[detail.asset.freshness]}}</span><small>观测：{{date(detail.asset.metrics?.observed_at)}}</small><button class="text-button" @click="editing=!editing">编辑分组与标签</button></div></div>
          <form v-if="editing" class="panel edit-form" @submit.prevent="saveAsset"><label>显示名称<input v-model="editName" required maxlength="128"/></label><label>管理分组<select v-model="editGroup"><option v-for="g in groups" :key="g.id" :value="g.id">{{g.name}}</option></select></label><label>标签（每行 key=value）<textarea v-model="editTags" rows="3"/></label><button class="primary" :disabled="busy">保存修改</button></form>
          <div v-if="detail.identity_conflicts?.length" class="warning banner"><Icon name="alert"/>发现相同机器指纹的其他资产线索，尚未处置。资产没有自动合并。</div>
          <div class="tabs"><button v-for="[value,label] in [['overview','主机概览'],['ports','端口'],['processes','进程'],['packages','软件包']]" :key="value" :class="{selected:tab===value}" @click="tab=value;tableSearch=''">{{label}}</button></div>
          <template v-if="tab==='overview'"><div class="stats"><div class="stat panel"><span>CPU 使用率</span><strong>{{percent(detail.asset.metrics?.cpu_percent)}}</strong><small>首次采样 / 计数器重置为未知</small></div><div class="stat panel"><span>内存使用率</span><strong>{{percent(memory(detail.asset))}}</strong><small>可用 {{bytes(detail.asset.metrics?.memory_available_bytes)}} / 总计 {{bytes(detail.asset.metrics?.memory_total_bytes)}}</small></div><div class="stat panel"><span>可见进程</span><strong>{{detail.asset.metrics?.process_count ?? '未知'}}</strong><small>进程数量，非线程数</small></div></div>
          <div class="detail-columns"><section class="panel"><div class="panel-head"><h2>主机信息</h2><span class="muted">Scout {{detail.asset.scout_version ?? '未知'}}</span></div><dl class="properties"><div v-for="[label,value] in [['发行版',[detail.inventory?.os_id,detail.inventory?.os_version].filter(Boolean).join(' ')],['内核',detail.inventory?.kernel_version],['架构',detail.inventory?.architecture],['CPU',detail.inventory?.cpu_model],['逻辑核数',detail.inventory?.logical_cpu_count],['启动 ID',detail.inventory?.boot_id]]" :key="String(label)"><dt>{{label}}</dt><dd>{{value ?? '未知'}}</dd></div></dl></section>
          <section class="panel"><div class="panel-head"><h2>采集覆盖</h2><span class="muted">不等于安全检查通过</span></div><div v-if="!Object.keys(coverage).length" class="empty small">尚无采集报告</div><div v-for="(c,key) in coverage" :key="key" class="coverage-row"><span>{{domainNames[key] ?? key}}</span><span class="status" :class="c.status">{{statusNames[c.status] ?? c.status}}</span><p v-if="c.reason">{{coverageReason(c.reason)}}</p></div></section></div>
          <section class="panel"><div class="panel-head"><h2>网卡当前计数</h2><span class="muted">按接口展示，不合并重复流量</span></div><div class="table-scroll"><table><thead><tr><th>接口</th><th>累计接收</th><th>累计发送</th><th>接收速率</th><th>发送速率</th></tr></thead><tbody><tr v-for="i in detail.inventory?.interfaces ?? []" :key="i.name"><td class="mono">{{i.name}}</td><td>{{bytes(i.rx_bytes)}}</td><td>{{bytes(i.tx_bytes)}}</td><td>{{i.rx_bytes_per_second==null?'未知':bytes(i.rx_bytes_per_second)+'/s'}}</td><td>{{i.tx_bytes_per_second==null?'未知':bytes(i.tx_bytes_per_second)+'/s'}}</td></tr></tbody></table></div><p v-if="!detail.inventory?.interfaces.length" class="empty small">暂无网卡观测</p></section>
          </template>
          <template v-else><section class="panel"><div class="panel-head"><h2>{{tab==='ports'?'TCP 监听 / UDP 绑定':tab==='packages'?'已采集软件包':'可见进程清单'}}</h2><label v-if="tab==='ports'" class="checkbox"><input v-model="hideLoopback" type="checkbox"/>隐藏回环地址</label><input v-else v-model="tableSearch" class="table-search" :placeholder="tab==='packages'?'搜索包名或版本':'搜索 PID 或进程名称'" aria-label="搜索清单"/></div><p class="table-note">{{tab==='packages'?'保留完整 Debian 版本；来源未知不表示安全，漏洞情报匹配未接入。':tab==='ports'?'本地端点不代表已验证公网可达性。Docker 发布映射尚未接入。':'只包含 PID、启动计数、名称和状态，不采集命令行或环境变量。'}}</p><div v-for="c in detail.collections.filter(c=>c.kind===(tab==='processes'?'inventory':tab))" :key="c.kind" class="collection-note"><span class="status" :class="c.latest_attempt.status">{{statusNames[c.latest_attempt.status] ?? c.latest_attempt.status}}</span> 最近尝试 {{date(c.latest_attempt.observed_at)}}<span>最近完整 {{date(c.latest_complete?.observed_at)}}</span></div>
          <div class="table-scroll"><table v-if="tab==='ports'"><thead><tr><th>协议</th><th>本地地址</th><th>端口</th><th>网络视图</th><th>范围</th></tr></thead><tbody><tr v-for="p in shownPorts" :key="p.protocol+p.address+p.port"><td>{{p.protocol.toUpperCase()}}</td><td class="mono">{{p.address}}</td><td class="mono">{{p.port}}</td><td>{{p.network_namespace}}</td><td>{{p.loopback?'回环':'非回环 / 未验证可达'}}</td></tr></tbody></table>
          <table v-else-if="tab==='processes'"><thead><tr><th>PID</th><th>进程名称</th><th>状态</th><th>启动 ticks</th></tr></thead><tbody><tr v-for="p in filteredProcesses.slice(0,300)" :key="p.pid+':'+p.start_ticks"><td class="mono">{{p.pid}}</td><td>{{p.name}}</td><td>{{p.state}}</td><td class="mono">{{p.start_ticks}}</td></tr></tbody></table>
          <table v-else><thead><tr><th>软件包</th><th>完整版本</th><th>架构</th><th>源包</th><th>来源</th></tr></thead><tbody><tr v-for="p in filteredPackages.slice(0,300)" :key="p.name+p.architecture"><td>{{p.name}}</td><td class="mono">{{p.version}}</td><td>{{p.architecture}}</td><td>{{p.source_name ?? '未知'}}</td><td>{{p.origin==='unknown'?'未知':p.origin}}</td></tr></tbody></table></div><div class="table-footer">{{tab==='ports'?shownPorts.length:tab==='processes'?filteredProcesses.length:filteredPackages.length}} 条匹配观测<span v-if="tab!=='ports'">每次展示前 300 条；输入搜索可缩小范围</span></div></section></template>
        </template>
        <template v-else-if="page==='assets'"><div class="stats"><div class="stat panel"><span>当前页资产</span><strong>{{assets.length}}</strong><small>与当前分组、名称筛选一致</small><Icon name="server"/></div><div class="stat panel"><span>近期有效指标</span><strong>{{freshCount}}<em> / {{assets.length}}</em></strong><small>观测时间在最近 2 分钟内</small><Icon name="activity"/></div><div class="stat panel"><span>已知 CPU 平均值</span><strong>{{averageCpu}}</strong><small>{{knownCpu.length}} 台有有效 CPU 值</small><Icon name="grid"/></div></div>
          <div class="scope"><span><Icon name="layers"/>管理分组<select v-model="group" @change="filter"><option value="">全部分组</option><option v-for="g in groups" :key="g.id" :value="g.id">{{g.name}}</option></select></span><small>最后读取 {{date(fetchedAt)}}</small></div><section class="panel"><div class="panel-head"><div><h2>主机清单</h2><p>注册身份独立，数据由 Scout 签名上报。</p></div><form class="search-box" @submit.prevent="filter"><Icon name="search"/><input v-model="search" maxlength="128" placeholder="按资产名称搜索" aria-label="按资产名称搜索"/><button type="submit">搜索</button></form></div>
          <div class="table-scroll"><table><thead><tr><th>主机 / 资产</th><th>管理分组</th><th>采集时效</th><th>CPU</th><th>内存</th><th>最近观测</th><th></th></tr></thead><tbody><tr v-for="a in assets" :key="a.id"><td><button class="host-link" @click="selectAsset(a.id)"><span class="mini-host"><Icon name="server"/></span><span>{{a.display_name}}<small>{{[a.os_id,a.os_version].filter(Boolean).join(' ') || '系统信息待采集'}}</small></span></button></td><td><span class="badge">{{a.group_name}}</span></td><td><span class="status" :class="a.freshness">{{statusNames[a.freshness]}}</span></td><td class="metric">{{percent(a.metrics?.cpu_percent)}}<div v-if="a.metrics?.cpu_percent != null" class="meter"><i :style="{width:a.metrics.cpu_percent+'%'}"/></div></td><td class="metric">{{percent(memory(a))}}<div v-if="memory(a)!=null" class="meter"><i :style="{width:memory(a)+'%'}"/></div></td><td class="muted small">{{date(a.metrics?.observed_at)}}</td><td><button class="text-button" @click="selectAsset(a.id)">查看 →</button></td></tr></tbody></table></div>
          <div v-if="!assets.length && !busy" class="empty"><Icon name="server"/><h3>{{search || group?'没有匹配的资产':'等待第一台主机登记'}}</h3><p>{{search || group?'调整筛选后重试。':'完成 Scout 身份初始化与管理员登记后，真实资产会显示在这里。'}}</p></div><div v-if="busy && !assets.length" class="empty">正在读取资产…</div><div class="table-footer"><span>本页 {{assets.length}} 台 · 每 30 秒刷新</span><div><button v-if="cursor" class="text-button" @click="cursor=null;refresh()">回到首页</button><button v-if="next" class="button" :disabled="busy" @click="more">下一页 →</button></div></div></section><div class="boundary-note"><Icon name="alert"/><p><strong>采集完整不等于安全。</strong> 漏洞情报、认证基线、AI 诊断与自动升级尚未接入。</p></div>
        </template>
        <template v-else-if="page==='groups'"><section class="panel"><div class="panel-head"><div><h2>管理分组</h2><p>每台主机属于一个分组，标签用于灵活筛选。</p></div></div><form class="create-group" @submit.prevent="createGroup"><input v-model="groupName" required maxlength="80" placeholder="新分组名称" aria-label="新分组名称"/><button class="primary" :disabled="busy || !groupName.trim()"><Icon name="plus"/>创建分组</button></form><div class="group-list"><div v-for="g in groups" :key="g.id"><span class="mini-host"><Icon name="layers"/></span><span><strong>{{g.name}}</strong><small>{{g.description || '暂无描述'}}</small></span><button class="text-button" @click="group=g.id;navigate('assets');filter()">查看资产 →</button></div></div></section></template>
        <template v-else><section class="panel capability-panel"><span class="capability-mark"><Icon name="shield"/></span><div class="eyebrow">PHASE A / READ-ONLY</div><h2>先建立可信的主机视图</h2><p>当前提供资产、采集清单和运行指标。系统不会将缺失的证据显示为检查通过。</p><div class="capability-grid"><article><Icon name="check"/><h3>已接入</h3><p>主机登记与签名上报<br>CPU / RAM / 网卡 / 进程 / 端口<br>软件包清单与采集覆盖<br>分组与标签管理</p></article><article><Icon name="clock"/><h3>尚未接入</h3><p>漏洞情报匹配与认证基线<br>AI 诊断与系统日志检索<br>自动升级与任务执行<br>历史指标聚合与保留调度</p></article></div><p class="warning-text">现有密码强度未验证。没有任意远程命令或自动处置接口。</p></section></template>
      </main><footer>Sentinel Hub <span>一期 A · 开发版 · 仅显示真实观测</span></footer>
    </div>
  </template>
</template>
