-- Versioned application migration; derived from docs/sql, SQLx owns the transaction.
-- PostgreSQL 17+ 设计草案；依次执行 001、002、003。不是可重复运行的迁移。
-- UUID 由应用分配。所有表统一使用 id 单列主键和 create_time、update_time、"delete" 元数据。
-- 已发布内容不可变、合法状态迁移、权限与跨行规则由应用事务和数据库权限共同保证。
-- 外键保证引用存在，不保证引用对象未软删；认证、授权、策略解析和下发须校验 NOT "delete"。
-- 软删不释放幂等键、历史版本号和在途互斥名额；角色/策略绑定允许软删后新建。
SET LOCAL search_path = sentinel, public, pg_catalog;

CREATE TABLE users (
    id uuid PRIMARY KEY,
    create_time timestamptz NOT NULL DEFAULT now(),
    update_time timestamptz NOT NULL DEFAULT now(),
    "delete" boolean NOT NULL DEFAULT false,
    display_name text NOT NULL,
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled'))
);
-- 登录方式另行确定；认证映射随后引入，不在此存储密码、令牌或私钥。
CREATE TABLE role_bindings (
    id uuid PRIMARY KEY,
    create_time timestamptz NOT NULL DEFAULT now(),
    update_time timestamptz NOT NULL DEFAULT now(),
    "delete" boolean NOT NULL DEFAULT false,
    user_id uuid NOT NULL REFERENCES users(id),
    role_code text NOT NULL CHECK (role_code IN ('admin', 'operator', 'viewer', 'release_manager')),
    scope_kind text NOT NULL CHECK (scope_kind IN ('global', 'group')),
    group_id uuid REFERENCES asset_groups(id),
    CHECK ((scope_kind = 'global' AND group_id IS NULL) OR
           (scope_kind = 'group' AND group_id IS NOT NULL)),
    CHECK (role_code <> 'admin' OR scope_kind = 'global')
);
CREATE UNIQUE INDEX role_bindings_global_uq ON role_bindings(user_id, role_code) WHERE scope_kind = 'global' AND NOT "delete";
CREATE UNIQUE INDEX role_bindings_group_uq ON role_bindings(user_id, role_code, group_id) WHERE scope_kind = 'group' AND NOT "delete";
CREATE INDEX role_bindings_group_idx ON role_bindings(group_id) WHERE group_id IS NOT NULL AND NOT "delete";
-- 内置角色的动作矩阵由应用定义；组权限也必须应用于日志查询、证据读取、导出和批量任务。
-- 权限检查同时要求用户、角色绑定、管理组和目标资产未软删；停用用户不因已有绑定继续授权。

CREATE TABLE policies (
    id uuid PRIMARY KEY,
    create_time timestamptz NOT NULL DEFAULT now(),
    update_time timestamptz NOT NULL DEFAULT now(),
    "delete" boolean NOT NULL DEFAULT false,
    name text NOT NULL UNIQUE,
    description text NOT NULL DEFAULT '',
    disabled_at timestamptz,
    created_by uuid REFERENCES users(id)
);
CREATE TABLE policy_revisions (
    id uuid PRIMARY KEY,
    create_time timestamptz NOT NULL DEFAULT now(),
    update_time timestamptz NOT NULL DEFAULT now(),
    "delete" boolean NOT NULL DEFAULT false,
    policy_id uuid NOT NULL REFERENCES policies(id),
    revision bigint NOT NULL CHECK (revision > 0),
    schema_version integer NOT NULL CHECK (schema_version > 0),
    content jsonb NOT NULL CHECK (jsonb_typeof(content) = 'object'),
    content_sha256 bytea NOT NULL CHECK (octet_length(content_sha256) = 32),
    published_by uuid REFERENCES users(id),
    published_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (policy_id, revision)
);
-- 此表只保存发布后的不可变内容。禁止原地编辑，通过新增 revision 表达变更。
-- 通用 update_time 和 "delete" 不放开正文编辑；逻辑隐藏也须保留历史引用和版本号唯一性。
CREATE TABLE policy_bindings (
    id uuid PRIMARY KEY,
    create_time timestamptz NOT NULL DEFAULT now(),
    update_time timestamptz NOT NULL DEFAULT now(),
    "delete" boolean NOT NULL DEFAULT false,
    policy_revision_id uuid NOT NULL REFERENCES policy_revisions(id),
    scope_kind text NOT NULL CHECK (scope_kind IN ('default', 'group', 'asset')),
    group_id uuid REFERENCES asset_groups(id),
    asset_id uuid REFERENCES assets(id),
    updated_by uuid REFERENCES users(id),
    CHECK ((scope_kind = 'default' AND group_id IS NULL AND asset_id IS NULL) OR
           (scope_kind = 'group' AND group_id IS NOT NULL AND asset_id IS NULL) OR
           (scope_kind = 'asset' AND asset_id IS NOT NULL AND group_id IS NULL))
);
CREATE UNIQUE INDEX policy_bindings_default_uq ON policy_bindings(scope_kind) WHERE scope_kind = 'default' AND NOT "delete";
CREATE UNIQUE INDEX policy_bindings_group_uq ON policy_bindings(group_id) WHERE scope_kind = 'group' AND NOT "delete";
CREATE UNIQUE INDEX policy_bindings_asset_uq ON policy_bindings(asset_id) WHERE scope_kind = 'asset' AND NOT "delete";
-- 每资产只有一个管理组。优先级 default < group < asset，整份覆盖；标签不参与权限和隐式合并。
-- 绑定或管理组变更后，事务化生成受影响资产的新目标；不能把异步通知当成已经生效。

CREATE TABLE scout_releases (
    id uuid PRIMARY KEY,
    create_time timestamptz NOT NULL DEFAULT now(),
    update_time timestamptz NOT NULL DEFAULT now(),
    "delete" boolean NOT NULL DEFAULT false,
    version_label text NOT NULL,
    image_reference text NOT NULL,
    image_digest text NOT NULL CHECK (image_digest ~ '^sha256:[0-9a-f]{64}$'),
    signature_metadata jsonb NOT NULL CHECK (jsonb_typeof(signature_metadata) = 'object'),
    platform_constraints jsonb NOT NULL CHECK (jsonb_typeof(platform_constraints) = 'object'),
    deployment_spec jsonb NOT NULL CHECK (jsonb_typeof(deployment_spec) = 'object'),
    deployment_schema_version integer NOT NULL CHECK (deployment_schema_version > 0),
    compatibility jsonb NOT NULL CHECK (jsonb_typeof(compatibility) = 'object'),
    status text NOT NULL DEFAULT 'available' CHECK (status IN ('available', 'disabled')),
    published_by uuid REFERENCES users(id),
    published_at timestamptz NOT NULL DEFAULT now()
);
-- 签名/兼容性/部署规格由应用验证并固定；禁用状态可变，已发布制品内容不可变。
-- 多架构 index 的平台 digest、协议和本地状态格式范围均进入受签名保护的发布内容。
CREATE TABLE asset_desired_states (
    id uuid PRIMARY KEY,
    create_time timestamptz NOT NULL DEFAULT now(),
    update_time timestamptz NOT NULL DEFAULT now(),
    "delete" boolean NOT NULL DEFAULT false,
    asset_id uuid NOT NULL REFERENCES assets(id),
    generation bigint NOT NULL CHECK (generation > 0),
    policy_revision_id uuid NOT NULL REFERENCES policy_revisions(id),
    release_id uuid REFERENCES scout_releases(id),
    resolved_config jsonb NOT NULL CHECK (jsonb_typeof(resolved_config) = 'object'),
    config_sha256 bytea NOT NULL CHECK (octet_length(config_sha256) = 32),
    reason text NOT NULL,
    created_by uuid REFERENCES users(id),
    UNIQUE (asset_id, generation),
    UNIQUE (asset_id, generation, release_id)
);
-- 追加式历史。release_id 为空表示尚未设置程序目标，不表示卸载；允许策略独立应用。
-- 更新目标须锁定当前行或使用 CAS，generation 严格递增；授权降级也使用新的 generation。
CREATE TABLE asset_control_states (
    id uuid PRIMARY KEY,
    create_time timestamptz NOT NULL DEFAULT now(),
    update_time timestamptz NOT NULL DEFAULT now(),
    "delete" boolean NOT NULL DEFAULT false,
    asset_id uuid NOT NULL UNIQUE REFERENCES assets(id),
    desired_generation bigint NOT NULL,
    applied_generation bigint,
    applied_policy_revision_id uuid REFERENCES policy_revisions(id),
    running_release_id uuid REFERENCES scout_releases(id),
    active_installation_id uuid,
    active_instance_id uuid,
    active_epoch bigint CHECK (active_epoch > 0),
    report_sequence bigint CHECK (report_sequence >= 0),
    reconcile_status text NOT NULL DEFAULT 'unknown' CHECK (reconcile_status IN ('unknown', 'pending', 'applying', 'applied', 'blocked')),
    reason_code text,
    last_reported_at timestamptz,
    FOREIGN KEY (asset_id, desired_generation) REFERENCES asset_desired_states(asset_id, generation),
    FOREIGN KEY (asset_id, applied_generation) REFERENCES asset_desired_states(asset_id, generation),
    FOREIGN KEY (active_installation_id, asset_id) REFERENCES scout_installations(id, asset_id),
    FOREIGN KEY (active_instance_id, asset_id, active_installation_id) REFERENCES scout_instances(id, asset_id, installation_id),
    CHECK (applied_generation IS NULL OR applied_generation <= desired_generation),
    CHECK ((active_instance_id IS NULL AND active_installation_id IS NULL AND active_epoch IS NULL) OR
           (active_instance_id IS NOT NULL AND active_installation_id IS NOT NULL AND active_epoch IS NOT NULL))
);
-- applied_generation 仅在整个目标确认收敛后推进；实际策略/版本可在过渡期间分别报告。
-- 活动实例仅为 Hub 观察值；宿主活动锁和本地升级记录负责互斥，不能由数据库 heartbeat 代替。
-- 旧实例补报可进入历史，但不得靠较晚的接收时间覆盖新实例当前状态。

CREATE TABLE tasks (
    id uuid PRIMARY KEY,
    create_time timestamptz NOT NULL DEFAULT now(),
    update_time timestamptz NOT NULL DEFAULT now(),
    "delete" boolean NOT NULL DEFAULT false,
    asset_id uuid NOT NULL REFERENCES assets(id),
    kind text NOT NULL CHECK (kind IN ('asset_collect', 'package_collect', 'port_collect', 'baseline_scan', 'diagnostic', 'upgrade')),
    state text NOT NULL DEFAULT 'queued' CHECK (state IN ('queued', 'accepted', 'running', 'cancel_requested', 'unknown', 'succeeded', 'failed', 'cancelled', 'expired')),
    origin text NOT NULL CHECK (origin IN ('manual', 'schedule', 'rollout', 'rule')),
    desired_generation bigint,
    parameters_schema_version integer NOT NULL CHECK (parameters_schema_version > 0),
    parameters jsonb NOT NULL CHECK (jsonb_typeof(parameters) = 'object'),
    created_by uuid REFERENCES users(id),
    idempotency_key text,
    request_sha256 bytea CHECK (octet_length(request_sha256) = 32),
    current_attempt_id uuid,
    not_before timestamptz NOT NULL DEFAULT now(),
    deadline_at timestamptz NOT NULL,
    cancel_requested_at timestamptz,
    finished_at timestamptz,
    UNIQUE (id, asset_id),
    UNIQUE (id, asset_id, kind),
    FOREIGN KEY (asset_id, desired_generation) REFERENCES asset_desired_states(asset_id, generation),
    CHECK (deadline_at > not_before),
    CHECK (kind <> 'upgrade' OR desired_generation IS NOT NULL),
    CHECK (idempotency_key IS NULL OR (created_by IS NOT NULL AND request_sha256 IS NOT NULL)),
    CHECK (NOT "delete" OR state IN ('succeeded', 'failed', 'cancelled', 'expired'))
);
CREATE UNIQUE INDEX tasks_request_uq ON tasks(created_by, idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE UNIQUE INDEX tasks_one_upgrade_uq ON tasks(asset_id)
    WHERE kind = 'upgrade' AND state IN ('queued', 'accepted', 'running', 'cancel_requested', 'unknown');
CREATE INDEX tasks_asset_history_idx ON tasks(asset_id, create_time DESC, id);
CREATE INDEX tasks_dispatch_idx ON tasks(not_before, id) WHERE state = 'queued';
-- parameters 必须按 kind 校验采集范围、超时和资源预算；不接受 Shell 或任意容器命令。
-- 同幂等 key 的不同请求摘要须报冲突。deadline/失联不能证明远端未执行；未知升级占用互斥名额。
CREATE TABLE task_attempts (
    id uuid PRIMARY KEY,
    create_time timestamptz NOT NULL DEFAULT now(),
    update_time timestamptz NOT NULL DEFAULT now(),
    "delete" boolean NOT NULL DEFAULT false,
    task_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    attempt_no integer NOT NULL CHECK (attempt_no > 0),
    state text NOT NULL DEFAULT 'dispatching' CHECK (state IN ('dispatching', 'accepted', 'running', 'unknown', 'succeeded', 'failed', 'cancelled', 'not_executed')),
    executor_installation_id uuid,
    executor_instance_id uuid,
    active_epoch bigint CHECK (active_epoch > 0),
    last_report_sequence bigint CHECK (last_report_sequence >= 0),
    accepted_at timestamptz,
    started_at timestamptz,
    finished_at timestamptz,
    error_code text,
    result_summary jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(result_summary) = 'object'),
    UNIQUE (task_id, attempt_no),
    UNIQUE (id, asset_id),
    UNIQUE (id, task_id, asset_id),
    FOREIGN KEY (task_id, asset_id) REFERENCES tasks(id, asset_id),
    FOREIGN KEY (executor_instance_id, asset_id, executor_installation_id) REFERENCES scout_instances(id, asset_id, installation_id),
    CHECK ((executor_instance_id IS NULL AND executor_installation_id IS NULL AND active_epoch IS NULL) OR
           (executor_instance_id IS NOT NULL AND executor_installation_id IS NOT NULL AND active_epoch IS NOT NULL)),
    CHECK (NOT "delete" OR state IN ('succeeded', 'failed', 'cancelled', 'not_executed'))
);
ALTER TABLE tasks ADD CONSTRAINT tasks_current_attempt_fk
    FOREIGN KEY (current_attempt_id, id, asset_id) REFERENCES task_attempts(id, task_id, asset_id);
CREATE UNIQUE INDEX task_attempts_one_open_uq ON task_attempts(task_id)
    WHERE state IN ('dispatching', 'accepted', 'running', 'unknown');
-- 非终态任务和尝试禁止软删；互斥索引不排除软删行，禁止以软删绕开执行/恢复状态机。
-- 消息重投复用 attempt ID；业务重试才新增 attempt，旧尝试迟到报告只更新对应历史。
-- Scout 本地可靠保存任务后确认接收，执行结果另行上报；确认消息不代表任务完成。
CREATE TABLE task_events (
    id uuid PRIMARY KEY,
    create_time timestamptz NOT NULL DEFAULT now(),
    update_time timestamptz NOT NULL DEFAULT now(),
    "delete" boolean NOT NULL DEFAULT false,
    task_id uuid NOT NULL,
    attempt_id uuid,
    asset_id uuid NOT NULL,
    instance_id uuid,
    report_sequence bigint CHECK (report_sequence >= 0),
    event_type text NOT NULL,
    details jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(details) = 'object'),
    occurred_at timestamptz,
    received_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (task_id, asset_id) REFERENCES tasks(id, asset_id),
    FOREIGN KEY (attempt_id, task_id, asset_id) REFERENCES task_attempts(id, task_id, asset_id),
    FOREIGN KEY (instance_id, asset_id) REFERENCES scout_instances(id, asset_id)
);
CREATE INDEX task_events_task_idx ON task_events(task_id, received_at, id);

CREATE TABLE upgrade_rollouts (
    id uuid PRIMARY KEY,
    create_time timestamptz NOT NULL DEFAULT now(),
    update_time timestamptz NOT NULL DEFAULT now(),
    "delete" boolean NOT NULL DEFAULT false,
    name text NOT NULL,
    release_id uuid NOT NULL REFERENCES scout_releases(id),
    state text NOT NULL DEFAULT 'draft' CHECK (state IN ('draft', 'running', 'paused', 'completed', 'cancelled')),
    max_parallel integer NOT NULL CHECK (max_parallel > 0),
    observation_seconds integer NOT NULL CHECK (observation_seconds > 0),
    pause_failure_ratio numeric(5,4) NOT NULL CHECK (pause_failure_ratio BETWEEN 0 AND 1),
    batch_plan jsonb NOT NULL CHECK (jsonb_typeof(batch_plan) = 'object'),
    created_by uuid NOT NULL REFERENCES users(id),
    started_at timestamptz,
    finished_at timestamptz
);
CREATE TABLE upgrade_targets (
    id uuid PRIMARY KEY,
    create_time timestamptz NOT NULL DEFAULT now(),
    update_time timestamptz NOT NULL DEFAULT now(),
    "delete" boolean NOT NULL DEFAULT false,
    rollout_id uuid NOT NULL REFERENCES upgrade_rollouts(id),
    asset_id uuid NOT NULL REFERENCES assets(id),
    batch_no integer NOT NULL CHECK (batch_no > 0),
    desired_generation bigint,
    task_id uuid UNIQUE,
    task_kind text NOT NULL DEFAULT 'upgrade' CHECK (task_kind = 'upgrade'),
    state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'scheduled', 'skipped', 'cancelled')),
    reason_code text,
    UNIQUE (rollout_id, asset_id),
    FOREIGN KEY (asset_id, desired_generation) REFERENCES asset_desired_states(asset_id, generation),
    FOREIGN KEY (task_id, asset_id, task_kind) REFERENCES tasks(id, asset_id, kind),
    CHECK (state <> 'scheduled' OR (task_id IS NOT NULL AND desired_generation IS NOT NULL))
);
CREATE INDEX upgrade_targets_batch_idx ON upgrade_targets(rollout_id, batch_no, state);
-- 固化当次目标集合；组/标签变化不追溯修改。执行结果读取 tasks，避免第二套完成状态。
-- 调度事务核对目标 release、权限、维护窗口和并发限制，再创建任务与目标 revision。
CREATE TABLE upgrade_attempt_details (
    id uuid PRIMARY KEY,
    create_time timestamptz NOT NULL DEFAULT now(),
    update_time timestamptz NOT NULL DEFAULT now(),
    "delete" boolean NOT NULL DEFAULT false,
    attempt_id uuid NOT NULL UNIQUE,
    task_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    task_kind text NOT NULL DEFAULT 'upgrade' CHECK (task_kind = 'upgrade'),
    desired_generation bigint NOT NULL,
    installation_id uuid NOT NULL,
    previous_release_id uuid REFERENCES scout_releases(id),
    target_release_id uuid NOT NULL REFERENCES scout_releases(id),
    old_instance_id uuid NOT NULL,
    candidate_instance_id uuid,
    old_container_id text,
    candidate_container_id text,
    phase text NOT NULL CHECK (phase IN ('preflight', 'pulling', 'candidate_starting', 'candidate_ready', 'handoff', 'observing', 'committed', 'rolling_back', 'rolled_back', 'failed', 'needs_recovery')),
    phase_sequence bigint NOT NULL CHECK (phase_sequence >= 0),
    observation_deadline_at timestamptz,
    committed_at timestamptz,
    rolled_back_at timestamptz,
    recovery_reason text,
    FOREIGN KEY (attempt_id, task_id, asset_id) REFERENCES task_attempts(id, task_id, asset_id),
    FOREIGN KEY (task_id, asset_id, task_kind) REFERENCES tasks(id, asset_id, kind),
    FOREIGN KEY (asset_id, desired_generation) REFERENCES asset_desired_states(asset_id, generation),
    FOREIGN KEY (asset_id, desired_generation, target_release_id) REFERENCES asset_desired_states(asset_id, generation, release_id),
    FOREIGN KEY (installation_id, asset_id) REFERENCES scout_installations(id, asset_id),
    FOREIGN KEY (old_instance_id, asset_id, installation_id) REFERENCES scout_instances(id, asset_id, installation_id),
    FOREIGN KEY (candidate_instance_id, asset_id, installation_id) REFERENCES scout_instances(id, asset_id, installation_id),
    CHECK (candidate_instance_id IS NULL OR candidate_instance_id <> old_instance_id)
);
-- 主机持久升级记录保留完整恢复规格；此处记录服务端可观察轨迹，不替代本地恢复状态。
-- 已提交后无可运行实例时可进入 needs_recovery；不能宣称数据库能自行执行镜像回滚。

CREATE TABLE outbox_messages (
    id uuid PRIMARY KEY,
    create_time timestamptz NOT NULL DEFAULT now(),
    update_time timestamptz NOT NULL DEFAULT now(),
    "delete" boolean NOT NULL DEFAULT false,
    message_type text NOT NULL CHECK (message_type IN ('task.dispatch', 'desired.changed', 'rollout.changed')),
    asset_id uuid REFERENCES assets(id),
    task_id uuid,
    attempt_id uuid,
    subject text NOT NULL,
    schema_version integer NOT NULL CHECK (schema_version > 0),
    payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'leased', 'published', 'failed')),
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    lease_token uuid,
    lease_until timestamptz,
    published_at timestamptz,
    last_error_code text,
    FOREIGN KEY (task_id, asset_id) REFERENCES tasks(id, asset_id),
    FOREIGN KEY (attempt_id, task_id, asset_id) REFERENCES task_attempts(id, task_id, asset_id),
    CHECK (task_id IS NULL OR asset_id IS NOT NULL),
    CHECK (attempt_id IS NULL OR task_id IS NOT NULL),
    CHECK (message_type <> 'task.dispatch' OR (task_id IS NOT NULL AND attempt_id IS NOT NULL)),
    CHECK (message_type <> 'desired.changed' OR asset_id IS NOT NULL),
    CHECK ((state = 'leased' AND lease_token IS NOT NULL AND lease_until IS NOT NULL) OR
           (state <> 'leased' AND lease_token IS NULL AND lease_until IS NULL)),
    CHECK ((state = 'published') = (published_at IS NOT NULL)),
    CHECK (NOT "delete" OR state IN ('published', 'failed'))
);
CREATE INDEX outbox_messages_ready_idx ON outbox_messages(next_attempt_at, id) WHERE state = 'pending';
CREATE INDEX outbox_messages_lease_idx ON outbox_messages(lease_until, id) WHERE state = 'leased';
-- 业务记录、审计与 outbox 同事务。发布进程用短事务 + SKIP LOCKED 领取租约，网络调用在事务外。
-- 获得 JetStream 发布确认后才标记 published；崩溃后重发复用相同 ID，消费者仍须幂等。
-- subject 由受控路由生成，不接收用户指定值。不能把 published 当作 Scout 已接收或执行成功。
CREATE TABLE inbox_receipts (
    id uuid PRIMARY KEY,
    create_time timestamptz NOT NULL DEFAULT now(),
    update_time timestamptz NOT NULL DEFAULT now(),
    "delete" boolean NOT NULL DEFAULT false,
    handler_key text NOT NULL,
    producer_installation_id uuid NOT NULL,
    event_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    producer_instance_id uuid,
    payload_sha256 bytea NOT NULL CHECK (octet_length(payload_sha256) = 32),
    received_at timestamptz NOT NULL DEFAULT now(),
    processed_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (handler_key, producer_installation_id, event_id),
    FOREIGN KEY (producer_installation_id, asset_id) REFERENCES scout_installations(id, asset_id),
    FOREIGN KEY (producer_instance_id, asset_id, producer_installation_id) REFERENCES scout_instances(id, asset_id, installation_id)
);
CREATE INDEX inbox_receipts_retention_idx ON inbox_receipts(processed_at);
-- 来源由认证身份绑定资产后确定，不能仅信 payload。receipt、业务修改与状态投影同事务，提交后 ACK。
-- 同 ID 不同摘要需报告冲突。handler_key 不随程序版本漂移；保留期覆盖允许的补传/重放窗口。
-- receipt 清理后仍依赖领域唯一键、任务尝试和单调序号防止旧消息破坏状态。
CREATE TABLE audit_events (
    id uuid PRIMARY KEY,
    create_time timestamptz NOT NULL DEFAULT now(),
    update_time timestamptz NOT NULL DEFAULT now(),
    "delete" boolean NOT NULL DEFAULT false,
    actor_kind text NOT NULL CHECK (actor_kind IN ('user', 'scout', 'system')),
    actor_user_id uuid REFERENCES users(id),
    actor_installation_id uuid,
    action text NOT NULL,
    asset_id uuid REFERENCES assets(id),
    target_type text NOT NULL,
    target_id text,
    request_id uuid,
    outcome text NOT NULL CHECK (outcome IN ('succeeded', 'denied', 'failed')),
    source_ip inet,
    details jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(details) = 'object'),
    occurred_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (actor_installation_id, asset_id) REFERENCES scout_installations(id, asset_id),
    CHECK ((actor_kind = 'user' AND actor_user_id IS NOT NULL AND actor_installation_id IS NULL) OR
           (actor_kind = 'scout' AND actor_installation_id IS NOT NULL AND actor_user_id IS NULL AND asset_id IS NOT NULL) OR
           (actor_kind = 'system' AND actor_user_id IS NULL AND actor_installation_id IS NULL))
);
CREATE INDEX audit_events_time_idx ON audit_events(occurred_at DESC, id);
CREATE INDEX audit_events_asset_idx ON audit_events(asset_id, occurred_at DESC) WHERE asset_id IS NOT NULL;
-- 审计 target 为历史引用，可指向多类对象；不用于权限判断或业务外键。正文仅保留必要脱敏差异。
-- 审计追加权限不能等同不可篡改；拒绝/失败请求在业务回滚后独立持久化审计，不能随回滚丢失。
-- audit_events 正文保持追加式；运行角色不得 UPDATE/DELETE，也不得设置 "delete" 隐藏审计。
-- 统一元数据触发器不授予修改权限；审计保留清理由独立角色执行并记录审计依据。
-- 历史保留及身份退役不使用级联删除；部署时分离迁移、运行和保留清理权限。
-- 应用事务的验收点：
-- 1. 策略发布与绑定更新不得改变历史 revision 的内容；有效配置摘要基于规范化序列化计算。
-- 2. 当前目标指针、待发送通知及成功审计同时提交；目标仍可能尚未被 Scout 应用。
-- 3. 资产换组时重新校验操作者权限并生成目标，旧任务是否继续按任务类型和授权范围决定。
-- 4. 多调度器锁定 rollout 后核算并发；部分唯一索引只保证单主机互斥，不保证批次并发上限。
-- 5. 新尝试必须确认上个尝试已结束或已完成恢复；unknown 不是可以安全重新执行的失败。
-- 6. 租约更新带 lease_token 条件，过期 worker 不得覆盖新领取者的 outbox 状态。
-- 7. 入站事务同时更新 inbox 与对应尝试；过期尝试报告不得改变 tasks.current_attempt_id。
-- 8. 候选启动不计成功；交接、观察、提交和回滚须按持久状态机处理并保留阶段事件。
-- 9. 发布禁用阻止新升级，不删除已有任务和历史引用；回滚授权使用新的目标 generation。
-- 10. 各 JSON 字段仍需大小限制、类型 schema 与敏感字段过滤，JSON object CHECK 不替代业务验证。
ALTER TABLE collection_runs ADD CONSTRAINT collection_runs_policy_revision_fk
    FOREIGN KEY (policy_revision_id) REFERENCES policy_revisions(id);
ALTER TABLE collection_runs ADD CONSTRAINT collection_runs_task_attempt_fk
    FOREIGN KEY (task_attempt_id, asset_id) REFERENCES task_attempts(id, asset_id);
-- 每张表独立挂载统一元数据触发器；函数在 001 中定义。
CREATE TRIGGER users_set_row_metadata
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION sentinel.set_row_metadata();
CREATE TRIGGER role_bindings_set_row_metadata
    BEFORE UPDATE ON role_bindings
    FOR EACH ROW EXECUTE FUNCTION sentinel.set_row_metadata();
CREATE TRIGGER policies_set_row_metadata
    BEFORE UPDATE ON policies
    FOR EACH ROW EXECUTE FUNCTION sentinel.set_row_metadata();
CREATE TRIGGER policy_revisions_set_row_metadata
    BEFORE UPDATE ON policy_revisions
    FOR EACH ROW EXECUTE FUNCTION sentinel.set_row_metadata();
CREATE TRIGGER policy_bindings_set_row_metadata
    BEFORE UPDATE ON policy_bindings
    FOR EACH ROW EXECUTE FUNCTION sentinel.set_row_metadata();
CREATE TRIGGER scout_releases_set_row_metadata
    BEFORE UPDATE ON scout_releases
    FOR EACH ROW EXECUTE FUNCTION sentinel.set_row_metadata();
CREATE TRIGGER asset_desired_states_set_row_metadata
    BEFORE UPDATE ON asset_desired_states
    FOR EACH ROW EXECUTE FUNCTION sentinel.set_row_metadata();
CREATE TRIGGER asset_control_states_set_row_metadata
    BEFORE UPDATE ON asset_control_states
    FOR EACH ROW EXECUTE FUNCTION sentinel.set_row_metadata();
CREATE TRIGGER tasks_set_row_metadata
    BEFORE UPDATE ON tasks
    FOR EACH ROW EXECUTE FUNCTION sentinel.set_row_metadata();
CREATE TRIGGER task_attempts_set_row_metadata
    BEFORE UPDATE ON task_attempts
    FOR EACH ROW EXECUTE FUNCTION sentinel.set_row_metadata();
CREATE TRIGGER task_events_set_row_metadata
    BEFORE UPDATE ON task_events
    FOR EACH ROW EXECUTE FUNCTION sentinel.set_row_metadata();
CREATE TRIGGER upgrade_rollouts_set_row_metadata
    BEFORE UPDATE ON upgrade_rollouts
    FOR EACH ROW EXECUTE FUNCTION sentinel.set_row_metadata();
CREATE TRIGGER upgrade_targets_set_row_metadata
    BEFORE UPDATE ON upgrade_targets
    FOR EACH ROW EXECUTE FUNCTION sentinel.set_row_metadata();
CREATE TRIGGER upgrade_attempt_details_set_row_metadata
    BEFORE UPDATE ON upgrade_attempt_details
    FOR EACH ROW EXECUTE FUNCTION sentinel.set_row_metadata();
CREATE TRIGGER outbox_messages_set_row_metadata
    BEFORE UPDATE ON outbox_messages
    FOR EACH ROW EXECUTE FUNCTION sentinel.set_row_metadata();
CREATE TRIGGER inbox_receipts_set_row_metadata
    BEFORE UPDATE ON inbox_receipts
    FOR EACH ROW EXECUTE FUNCTION sentinel.set_row_metadata();
CREATE TRIGGER audit_events_set_row_metadata
    BEFORE UPDATE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION sentinel.set_row_metadata();
