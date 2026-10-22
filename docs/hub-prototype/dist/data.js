/* Sentinel Hub prototype: deterministic fictional data, with no network requests. */
(function () {
  'use strict';

  var groups = ['生产环境', '预发布环境', '测试环境', '基础设施', '数据平台', '边缘节点'];
  var groupLimits = [480, 624, 828, 1008, 1152, 1248];
  var prefixes = ['prod', 'staging', 'test', 'infra', 'data', 'edge'];
  var seed = 20261021;
  function random() {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    return seed / 4294967296;
  }
  function integer(min, max) { return Math.floor(random() * (max - min + 1)) + min; }
  function pad(value, width) { return String(value).padStart(width, '0'); }
  function history(value) {
    return Array.from({ length: 24 }, function (_, i) {
      return Math.max(2, Math.min(99, Math.round(value - 10 + Math.sin(i * 0.64) * 9 + random() * 12)));
    }).map(function (point, i) { return i === 23 ? value : point; });
  }

  var featuredNames = ['prod-api-01', 'prod-db-01', 'prod-worker-03', 'edge-gateway-01', 'prod-web-02', 'prod-cache-01', 'prod-api-02', 'prod-worker-01', 'prod-web-01', 'prod-db-02', 'prod-cache-02', 'prod-api-03'];
  var assets = Array.from({ length: 1248 }, function (_, i) {
    var groupIndex = groupLimits.findIndex(function (limit) { return i < limit; });
    if (i === 3) groupIndex = 5;
    var status = i > 40 && i % 37 === 0 ? 'offline' : i > 40 && i % 29 === 0 ? 'stale' : 'online';
    var coverage = status === 'offline' ? 'failed' : status === 'stale' || (i > 40 && i % 43 === 0) ? 'partial' : 'complete';
    var role = ['api', 'worker', 'web', 'db', 'cache', 'gateway'][i % 6];
    var cpu = i === 0 ? 87 : i === 2 ? 94 : integer(4, 72);
    var memory = i === 1 ? 91 : i === 2 ? 84 : integer(18, 78);
    var asset = {
      id: 'asset-' + pad(i + 1, 4),
      name: featuredNames[i] || prefixes[groupIndex] + '-' + role + '-' + pad(i + 1, 3),
      ip: '10.' + (20 + groupIndex) + '.' + Math.floor(i / 250) + '.' + ((i % 250) + 2),
      group: groups[groupIndex],
      tags: ['region:sg-1', 'role:' + (i === 0 ? 'api' : i === 1 ? 'db' : i === 2 ? 'worker' : i === 3 ? 'gateway' : role), i % 4 === 0 ? 'tier:critical' : 'tier:standard'],
      os: i % 3 === 0 ? 'Ubuntu 22.04' : 'Ubuntu 24.04',
      arch: i % 5 === 0 ? 'arm64' : 'amd64',
      status: status,
      cpu: cpu,
      memory: memory,
      processes: integer(126, 442),
      ports: i === 0 ? 8 : integer(4, 24),
      version: i % 4 === 1 ? '0.9.0' : '0.8.4',
      lastSeen: status === 'offline' ? '2026-10-21T00:38:00Z' : status === 'stale' ? '2026-10-21T02:10:00Z' : '2026-10-21T02:42:' + pad(i % 30, 2) + 'Z',
      coverage: coverage,
      risk: 'none',
      vulnerabilities: 0,
      baselineFailed: 0,
      baselineUnknown: 0,
      cpuHistory: history(cpu),
      memoryHistory: history(memory),
      metricsStale: status !== 'online',
      rxRate: integer(120, 18400) * 1024,
      txRate: integer(60, 9200) * 1024,
      memoryTotal: [8, 16, 32, 64][i % 4],
      cores: [4, 8, 16, 32][i % 4],
      diskUsed: integer(22, 83),
      packageCount: integer(634, 1432),
      packageSnapshotAt: i === 1 || status !== 'online' ? '2026-10-20T02:40:00Z' : '2026-10-21T02:40:00Z',
      packageSnapshotStale: i === 1 || status !== 'online',
      packageAttemptStatus: i === 1 || status === 'offline' ? 'failed' : coverage,
      passwordStrengthVerified: false
    };
    return asset;
  });

  var ruleDefinitions = [
    ['SSH-PASSWORD', '禁用 SSH 密码认证', 'high', '检查 PasswordAuthentication 与有效配置上下文。'],
    ['SSH-ROOT', '限制 root 直接登录', 'high', '检查 PermitRootLogin 的配置与例外。'],
    ['SSH-EMPTY', '禁止空密码认证', 'critical', '检查 PermitEmptyPasswords；不读取密码或散列。'],
    ['SSH-INTERACTIVE', '核对交互式认证策略', 'medium', '交互式认证可用于多因素认证，须结合认证链判断。'],
    ['SSH-MATCH', '检查 Match 条件与包含配置', 'high', '检查 Include 与 Match 的覆盖；运行中生效情况可能无法确认。'],
    ['PAM-QUALITY', '启用密码质量策略', 'medium', '检查 PAM 质量要求与例外；现有密码强度未验证。'],
    ['PAM-REUSE', '检查密码历史策略', 'medium', '检查 PAM 密码复用限制；现有密码强度未验证。'],
    ['SSH-ALLOWLIST', '限制可登录用户范围', 'medium', '检查用户与组访问规则；按管理组策略评估。']
  ];
  var baselineRules = ruleDefinitions.map(function (rule) {
    return { ruleKey: rule[0], title: rule[1], severity: rule[2], note: rule[3], pass: 0, fail: 0, unknown: 0 };
  });
  var packages = [
    { name: 'openssl', installed: '3.0.2-0ubuntu1.18', fixed: '3.0.2-0ubuntu1.19', title: 'OpenSSL 软件包需要安全更新', severity: 'critical' },
    { name: 'openssh-server', installed: '1:8.9p1-3ubuntu0.10', fixed: '1:8.9p1-3ubuntu0.11', title: 'OpenSSH 安全更新待安装', severity: 'high' },
    { name: 'linux-image-generic', installed: '6.8.0-51.52', fixed: '6.8.0-52.53', title: '内核软件包存在待处理安全更新', severity: 'high' },
    { name: 'curl', installed: '8.5.0-2ubuntu10.3', fixed: '8.5.0-2ubuntu10.4', title: 'curl 软件包版本命中演示规则', severity: 'medium' },
    { name: 'libc6', installed: '2.39-0ubuntu8.3', fixed: '2.39-0ubuntu8.4', title: '系统运行库安全更新待安装', severity: 'high' },
    { name: 'sudo', installed: '1.9.15p5-3ubuntu5', fixed: '1.9.15p5-3ubuntu5.1', title: 'sudo 软件包需要复查', severity: 'high' },
    { name: 'libxml2', installed: '2.9.14+dfsg-1.3ubuntu3.2', fixed: '2.9.14+dfsg-1.3ubuntu3.3', title: 'XML 运行库安全更新待安装', severity: 'medium' }
  ];
  var affectedAssetIndexes = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 30, 33, 37, 42, 67, 91, 123, 166, 208, 255, 321, 477, 630, 803, 1002, 1201];
  var findings = affectedAssetIndexes.map(function (assetIndex, index) {
    var item = packages[index % packages.length];
    var state = index >= 25 ? 'resolved' : index === 19 || index === 22 ? 'unknown' : 'present';
    return {
      id: 'finding-' + pad(index + 1, 3),
      title: item.title,
      kind: 'vulnerability',
      assetId: assets[assetIndex].id,
      severity: item.severity,
      technicalState: state,
      disposition: index === 5 || index === 14 ? 'accepted_risk' : index % 4 === 1 ? 'acknowledged' : 'open',
      package: item.name,
      installedVersion: state === 'resolved' ? item.fixed : item.installed,
      fixedVersion: item.fixed,
      cve: 'DEMO-CVE-' + pad(index + 1, 3),
      rule: '',
      summary: '虚构演示记录，仅用于界面评审；编号、版本组合与修复关系不代表真实漏洞情报。' + (state === 'unknown' ? ' 当前软件包来源或覆盖不足，结论待确认。' : ''),
      evidence: '演示软件包清单 · ' + assets[assetIndex].os + ' · ' + assets[assetIndex].arch + ' · 匹配器 demo-r3。完整软件包版本与发行版共同参与判定；未执行利用验证。',
      firstSeen: '2026-10-' + pad(14 + index % 6, 2) + 'T03:20:00Z',
      lastSeen: '2026-10-21T02:35:00Z'
    };
  });
  var baselineAssetIndexes = [0, 1, 2, 3, 4, 5, 6, 7, 10, 12, 14, 16, 18, 20, 22, 24];
  baselineAssetIndexes.forEach(function (assetIndex, index) {
    var rule = ruleDefinitions[index % ruleDefinitions.length];
    var state = index === 14 ? 'resolved' : index === 13 || index === 15 ? 'unknown' : 'present';
    var evidence = [
      '演示脱敏证据：PasswordAuthentication yes；默认连接上下文的磁盘配置。运行中配置是否重载尚未确认。',
      '演示脱敏证据：PermitRootLogin yes；按生产组策略要求限制直接登录。',
      '演示脱敏证据：PermitEmptyPasswords yes；未采集任何密码或密码散列。',
      '演示脱敏证据：交互式认证已启用，但认证链与管理组要求不一致；不将交互式认证直接等同于密码登录。',
      '演示脱敏证据：一个 Match 上下文未达到策略要求；仅代表已检查的上下文。',
      '演示脱敏证据：密码质量模块未达到管理组要求。现有密码强度未验证。',
      '演示脱敏证据：密码历史要求未达到管理组策略。现有密码强度未验证。',
      '演示脱敏证据：用户范围未配置为管理组期望的受限集合。'
    ][index % 8];
    findings.push({
      id: 'finding-' + pad(29 + index, 3),
      title: rule[1],
      kind: 'baseline',
      assetId: assets[assetIndex].id,
      severity: rule[2],
      technicalState: state,
      disposition: index === 4 ? 'accepted_risk' : index % 3 === 1 ? 'acknowledged' : 'open',
      package: '',
      installedVersion: '',
      fixedVersion: '',
      cve: '',
      rule: rule[0],
      summary: '虚构的配置检查示例。' + rule[3] + (state === 'unknown' ? ' 本次证据不足，保留待确认状态。' : state === 'resolved' ? ' 最近完整复查符合策略要求。' : ''),
      evidence: state === 'resolved' ? '演示证据：最近完整复查已符合规则要求。旧证据仅保留在历史记录中。' : state === 'unknown' ? '演示证据：当前上下文未获得完整可核对结果，不能判定通过或修复。' : evidence,
      firstSeen: '2026-10-19T01:10:00Z',
      lastSeen: '2026-10-21T02:36:00Z'
    });
  });

  var severityOrder = { none: 0, medium: 1, high: 2, critical: 3 };
  var assetById = Object.fromEntries(assets.map(function (asset) { return [asset.id, asset]; }));
  findings.forEach(function (finding) {
    var asset = assetById[finding.assetId];
    if (finding.technicalState === 'present') {
      if (finding.kind === 'vulnerability') asset.vulnerabilities += 1;
      if (severityOrder[finding.severity] > severityOrder[asset.risk]) asset.risk = finding.severity;
    }
  });
  assets.forEach(function (asset) {
    var states = ruleDefinitions.map(function (_, index) {
      return asset.coverage === 'failed' || asset.coverage === 'partial' && index >= 5 ? 'unknown' : 'pass';
    });
    findings.filter(function (finding) { return finding.assetId === asset.id && finding.kind === 'baseline'; }).forEach(function (finding) {
      var ruleIndex = ruleDefinitions.findIndex(function (rule) { return rule[0] === finding.rule; });
      states[ruleIndex] = finding.technicalState === 'present' ? 'fail' : finding.technicalState === 'resolved' ? 'pass' : 'unknown';
    });
    states.forEach(function (state, index) { baselineRules[index][state] += 1; });
    asset.baselineFailed = states.filter(function (state) { return state === 'fail'; }).length;
    asset.baselineUnknown = states.filter(function (state) { return state === 'unknown'; }).length;
    asset.baselineStates = states;
  });

  var tasks = [
    { id: 'task-1008', assetId: 'asset-0003', name: 'CPU 异常专项诊断', kind: 'diagnostic', state: 'running', createdAt: '2026-10-21T02:41:00Z', progress: 64 },
    { id: 'task-1007', assetId: 'asset-0001', name: 'SSH 配置基线复查', kind: 'baseline', state: 'succeeded', createdAt: '2026-10-21T02:36:00Z', progress: 100 },
    { id: 'task-1006', assetId: 'asset-0002', name: '软件包清单采集', kind: 'packages', state: 'failed', createdAt: '2026-10-21T02:31:00Z', progress: 42, detail: '演示：采集期间读取失败；最近完整结果保留，风险未自动关闭。' },
    { id: 'task-1005', assetId: 'asset-0075', name: 'Scout 0.9.0 灰度升级', kind: 'upgrade', state: 'unknown', createdAt: '2026-10-21T02:21:00Z', progress: 70, detail: '演示：交接后连接中断，执行结果待确认，不能直接重复派发。' },
    { id: 'task-1004', assetId: 'asset-0004', name: '宿主机端口复查', kind: 'ports', state: 'queued', createdAt: '2026-10-21T02:40:00Z', progress: 0 }
  ];
  var releases = [
    { version: '0.9.0', channel: '灰度', compatible: ['Ubuntu 22.04 / amd64', 'Ubuntu 22.04 / arm64', 'Ubuntu 24.04 / amd64', 'Ubuntu 24.04 / arm64'], description: '演示版本：改进采集覆盖说明、端口视图与升级交接观测。' },
    { version: '0.8.4', channel: '稳定', compatible: ['Ubuntu 22.04 / amd64', 'Ubuntu 22.04 / arm64', 'Ubuntu 24.04 / amd64', 'Ubuntu 24.04 / arm64'], description: '演示版本：资产、指标、软件包清单与 SSH 基线采集。' }
  ];
  var policies = [
    { id: 'policy-default', name: '全局默认采集策略', scope: '全局默认', revision: 12, assetCount: assets.filter(function (asset) { return asset.group !== '生产环境' && asset.id !== 'asset-0004'; }).length, status: '已发布', updatedAt: '2026-10-20T07:30:00Z', description: '指标采样 60 秒；软件包清单每 6 小时；基线每日；结构化诊断只读。' },
    { id: 'policy-production', name: '生产环境安全基线', scope: '管理组 · 生产环境', revision: 8, assetCount: assets.filter(function (asset) { return asset.group === '生产环境'; }).length, status: '已发布', updatedAt: '2026-10-21T01:20:00Z', description: '整份覆盖默认策略；基线每 6 小时；限制 SSH 密码认证与 root 登录。' },
    { id: 'policy-edge', name: '边缘网关低资源策略', scope: '资产 · edge-gateway-01', revision: 3, assetCount: 1, status: '已发布', updatedAt: '2026-10-19T05:10:00Z', description: '资产级整份覆盖；限制诊断并发与采集资源，保留数据覆盖状态。' }
  ];
  var activity = [
    { title: 'prod-worker-03 CPU 持续偏高', description: '已创建只读诊断任务，正在整理进程与资源证据。', time: '1 分钟前', type: 'warning' },
    { title: 'prod-api-01 基线复查完成', description: '磁盘配置结果已更新，运行中生效情况单独标识。', time: '6 分钟前', type: 'success' },
    { title: 'Scout 升级结果待确认', description: 'asset-0075 交接后连接中断，升级任务保留未知状态。', time: '21 分钟前', type: 'warning' },
    { title: '生产环境策略修订已发布', description: '发布 r8，按管理组生成新的期望状态代次。', time: '1 小时前', type: 'info' },
    { title: '演示漏洞情报重新评估完成', description: '沿用已有软件包清单；清单采集时间保持不变。', time: '2 小时前', type: 'info' }
  ];

  window.SENTINEL_DATA = {
    assets: assets,
    findings: findings,
    baselineRules: baselineRules,
    tasks: tasks,
    releases: releases,
    policies: policies,
    activity: activity,
    groups: groups,
    demo: true,
    snapshotAt: '2026-10-21T02:42:30Z',
    dataNotice: '全部主机、任务、版本及漏洞记录均为虚构演示数据；现有密码强度未验证。'
  };
}());
