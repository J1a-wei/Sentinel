-- Versioned application migration; derived from docs/sql, SQLx owns the transaction.
-- 设计草案：资产、身份、采集快照与指标。面向全新空库，非生产迁移脚本。
-- PostgreSQL 17+；UUID 由 Rust 应用生成，无扩展依赖。执行顺序 001 -> 002 -> 003。
CREATE SCHEMA sentinel;
SET LOCAL search_path = sentinel, public, pg_catalog;

-- 通用元数据：业务 ID 与创建时间不可修改，更新/软删除均自动刷新更新时间。
-- 不替代领域状态机、审计追加权限或已发布正文的不可变约束。
CREATE FUNCTION sentinel.set_row_metadata() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.create_time IS DISTINCT FROM OLD.create_time THEN
        RAISE EXCEPTION 'id and create_time are immutable'
            USING ERRCODE = '23514', CONSTRAINT = 'row_metadata_immutable';
    END IF;
    NEW.update_time := GREATEST(clock_timestamp(), OLD.update_time + interval '1 microsecond', NEW.create_time);
    RETURN NEW;
END;
$$;

CREATE TABLE asset_groups (
    id uuid PRIMARY KEY,
    create_time timestamptz NOT NULL DEFAULT now(),
    update_time timestamptz NOT NULL DEFAULT now(),
    "delete" boolean NOT NULL DEFAULT false,
    name text NOT NULL CHECK (name <> ''),
    description text NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX asset_groups_name_live_uq ON asset_groups(name) WHERE NOT "delete";
CREATE TABLE assets (
    id uuid PRIMARY KEY,
    create_time timestamptz NOT NULL DEFAULT now(),
    update_time timestamptz NOT NULL DEFAULT now(),
    "delete" boolean NOT NULL DEFAULT false,
    group_id uuid NOT NULL REFERENCES asset_groups(id),
    display_name text NOT NULL CHECK (display_name <> ''),
    lifecycle text NOT NULL DEFAULT 'active' CHECK (lifecycle IN ('active', 'retired')),
    retired_at timestamptz,
    CHECK ((lifecycle = 'retired') = (retired_at IS NOT NULL)),
    CHECK (NOT "delete" OR lifecycle = 'retired')
);
CREATE INDEX assets_group_idx ON assets(group_id, lifecycle, id);
CREATE TABLE asset_tags (
    id uuid PRIMARY KEY,
    create_time timestamptz NOT NULL DEFAULT now(),
    update_time timestamptz NOT NULL DEFAULT now(),
    "delete" boolean NOT NULL DEFAULT false,
    asset_id uuid NOT NULL REFERENCES assets(id),
    key text NOT NULL CHECK (key <> ''),
    value text NOT NULL
);
CREATE UNIQUE INDEX asset_tags_live_uq ON asset_tags(asset_id, key) WHERE NOT "delete";
CREATE INDEX asset_tags_filter_idx ON asset_tags(key, value, asset_id) WHERE NOT "delete";
-- 一期管理组为扁平结构；每资产必属一组。标签只筛选，不参与权限继承。

CREATE TABLE scout_installations (
    id uuid PRIMARY KEY,
    create_time timestamptz NOT NULL DEFAULT now(),
    update_time timestamptz NOT NULL DEFAULT now(),
    "delete" boolean NOT NULL DEFAULT false,
    asset_id uuid NOT NULL REFERENCES assets(id),
    generation bigint NOT NULL CHECK (generation > 0),
    status text NOT NULL DEFAULT 'quarantined' CHECK (status IN ('active', 'quarantined', 'revoked')),
    registered_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    UNIQUE (id, asset_id),
    UNIQUE (asset_id, generation),
    CHECK ((status = 'revoked') = (revoked_at IS NOT NULL)),
    CHECK (NOT "delete" OR status = 'revoked')
);
CREATE UNIQUE INDEX scout_installations_active_uq ON scout_installations(asset_id) WHERE status = 'active';
CREATE TABLE scout_credentials (
    id uuid PRIMARY KEY,
    create_time timestamptz NOT NULL DEFAULT now(),
    update_time timestamptz NOT NULL DEFAULT now(),
    "delete" boolean NOT NULL DEFAULT false,
    installation_id uuid NOT NULL REFERENCES scout_installations(id),
    credential_sha256 bytea NOT NULL UNIQUE CHECK (octet_length(credential_sha256) = 32),
    public_key_sha256 bytea NOT NULL CHECK (octet_length(public_key_sha256) = 32),
    issuer_reference text NOT NULL,
    valid_from timestamptz NOT NULL,
    valid_until timestamptz NOT NULL,
    revoked_at timestamptz,
    CHECK (valid_until > valid_from),
    CHECK (NOT "delete" OR revoked_at IS NOT NULL)
);
CREATE INDEX scout_credentials_installation_idx ON scout_credentials(installation_id);
CREATE INDEX scout_credentials_public_key_idx ON scout_credentials(public_key_sha256);
-- 保存公开凭证指纹和有效期；不保存 Scout 私钥、注册令牌明文或部署密钥。
-- 凭证本体摘要唯一；公钥可复用，允许同一密钥续期时两份凭证短暂并行有效。
-- 凭证有效不代表安装身份仍处于 active。
CREATE TABLE scout_instances (
    id uuid PRIMARY KEY,
    create_time timestamptz NOT NULL DEFAULT now(),
    update_time timestamptz NOT NULL DEFAULT now(),
    "delete" boolean NOT NULL DEFAULT false,
    asset_id uuid NOT NULL,
    installation_id uuid NOT NULL,
    role text NOT NULL CHECK (role IN ('active', 'candidate', 'observer', 'exited')),
    version text NOT NULL,
    container_id text,
    boot_id uuid,
    active_epoch bigint CHECK (active_epoch > 0),
    capabilities jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(capabilities) = 'object'),
    started_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    ended_at timestamptz,
    UNIQUE (id, asset_id),
    UNIQUE (id, asset_id, installation_id),
    FOREIGN KEY (installation_id, asset_id) REFERENCES scout_installations(id, asset_id),
    CHECK (role <> 'active' OR active_epoch IS NOT NULL),
    CHECK ((role = 'exited') = (ended_at IS NOT NULL)),
    CHECK (NOT "delete" OR role = 'exited')
);
CREATE UNIQUE INDEX scout_instances_active_uq ON scout_instances(asset_id) WHERE role = 'active';
CREATE INDEX scout_instances_installation_idx ON scout_instances(installation_id, started_at DESC);
-- active 是 Hub 接纳的投影；数据库唯一键不能阻止两台克隆机器使用同一凭证。
-- 交接须在事务中先移出旧 active，再接纳新实例；宿主本地锁负责实际互斥。
CREATE TABLE asset_fingerprint_observations (
    id uuid PRIMARY KEY,
    create_time timestamptz NOT NULL DEFAULT now(),
    update_time timestamptz NOT NULL DEFAULT now(),
    "delete" boolean NOT NULL DEFAULT false,
    asset_id uuid NOT NULL,
    instance_id uuid NOT NULL,
    algorithm_revision text NOT NULL,
    fingerprint_sha256 bytea NOT NULL CHECK (octet_length(fingerprint_sha256) = 32),
    observed_at timestamptz NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (instance_id, asset_id) REFERENCES scout_instances(id, asset_id)
);
CREATE INDEX fingerprint_lookup_idx ON asset_fingerprint_observations(algorithm_revision, fingerprint_sha256);
CREATE INDEX fingerprint_asset_idx ON asset_fingerprint_observations(asset_id, received_at DESC);
CREATE TABLE identity_conflicts (
    id uuid PRIMARY KEY,
    create_time timestamptz NOT NULL DEFAULT now(),
    update_time timestamptz NOT NULL DEFAULT now(),
    "delete" boolean NOT NULL DEFAULT false,
    asset_id uuid NOT NULL REFERENCES assets(id),
    other_asset_id uuid REFERENCES assets(id),
    reason_code text NOT NULL,
    state text NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'resolved')),
    evidence jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(evidence) = 'object'),
    detected_at timestamptz NOT NULL DEFAULT now(),
    resolved_at timestamptz,
    resolution_note text,
    CHECK (other_asset_id IS NULL OR other_asset_id <> asset_id),
    CHECK ((state = 'resolved') = (resolved_at IS NOT NULL)),
    CHECK (state <> 'resolved' OR resolution_note IS NOT NULL)
);
CREATE INDEX identity_conflicts_open_idx ON identity_conflicts(asset_id) WHERE state = 'open';
-- 指纹索引故意不唯一；派生值变化/相同均不能直接证明是同一台机器。

CREATE TABLE package_snapshots (
    id uuid PRIMARY KEY,
    create_time timestamptz NOT NULL DEFAULT now(),
    update_time timestamptz NOT NULL DEFAULT now(),
    "delete" boolean NOT NULL DEFAULT false,
    asset_id uuid NOT NULL REFERENCES assets(id),
    content_sha256 bytea NOT NULL CHECK (octet_length(content_sha256) = 32),
    schema_version integer NOT NULL CHECK (schema_version > 0),
    os_id text NOT NULL,
    os_version text NOT NULL,
    architecture text NOT NULL,
    package_count integer NOT NULL CHECK (package_count >= 0),
    UNIQUE (id, asset_id),
    UNIQUE (asset_id, content_sha256)
);
CREATE TABLE package_entries (
    id uuid PRIMARY KEY,
    create_time timestamptz NOT NULL DEFAULT now(),
    update_time timestamptz NOT NULL DEFAULT now(),
    "delete" boolean NOT NULL DEFAULT false,
    snapshot_id uuid NOT NULL REFERENCES package_snapshots(id),
    package_name text NOT NULL CHECK (package_name <> ''),
    architecture text NOT NULL CHECK (architecture <> ''),
    version text NOT NULL CHECK (version <> ''),
    source_name text,
    source_version text,
    origin_status text NOT NULL CHECK (origin_status IN ('ubuntu', 'third_party', 'unknown')),
    origin_evidence jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(origin_evidence) = 'object'),
    UNIQUE (snapshot_id, package_name, architecture),
    CHECK ((source_name IS NULL) = (source_version IS NULL))
);
-- 不可变内容；摘要覆盖排序后的完整清单、来源、发行版、源包版本和 schema。
-- 内容相同的后续采集复用快照，但每次仍记录独立 run，不能把快照创建时间当采集时间。

CREATE TABLE collection_runs (
    id uuid PRIMARY KEY,
    create_time timestamptz NOT NULL DEFAULT now(),
    update_time timestamptz NOT NULL DEFAULT now(),
    "delete" boolean NOT NULL DEFAULT false,
    asset_id uuid NOT NULL,
    installation_id uuid NOT NULL,
    instance_id uuid NOT NULL,
    active_epoch bigint NOT NULL CHECK (active_epoch > 0),
    sequence bigint NOT NULL CHECK (sequence >= 0),
    kind text NOT NULL CHECK (kind IN ('inventory', 'packages', 'ports', 'baseline', 'diagnostic')),
    scope_key text NOT NULL DEFAULT 'host' CHECK (scope_key <> ''),
    status text NOT NULL CHECK (status IN ('running', 'complete', 'partial', 'failed', 'cancelled')),
    schema_version integer NOT NULL CHECK (schema_version > 0),
    collector_revision text NOT NULL,
    policy_revision_id uuid,
    task_attempt_id uuid,
    package_snapshot_id uuid,
    expected_scope jsonb NOT NULL CHECK (jsonb_typeof(expected_scope) = 'object'),
    rule_manifest jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(rule_manifest) = 'array'),
    coverage jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(coverage) = 'object'),
    result_summary jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(result_summary) = 'object'),
    started_at timestamptz NOT NULL,
    finished_at timestamptz,
    received_at timestamptz NOT NULL DEFAULT now(),
    error_code text,
    UNIQUE (id, asset_id),
    UNIQUE (id, asset_id, kind),
    UNIQUE (id, asset_id, kind, scope_key),
    UNIQUE (installation_id, sequence),
    FOREIGN KEY (instance_id, asset_id, installation_id) REFERENCES scout_instances(id, asset_id, installation_id),
    FOREIGN KEY (package_snapshot_id, asset_id) REFERENCES package_snapshots(id, asset_id),
    CHECK ((status = 'running') = (finished_at IS NULL)),
    CHECK (finished_at IS NULL OR finished_at >= started_at),
    CHECK (package_snapshot_id IS NULL OR kind = 'packages'),
    CHECK (kind <> 'packages' OR status <> 'complete' OR package_snapshot_id IS NOT NULL),
    CHECK (NOT "delete" OR status <> 'running')
);
CREATE INDEX collection_runs_asset_idx ON collection_runs(asset_id, kind, received_at DESC, id);
-- sequence 在安装身份下持久递增，新运行在本地先落盘分配。重复投递复用 run ID/sequence。
-- scope_key 区分整机与专项；rule_manifest 固定规则修订和预期上下文，不用缺行表示 pass。
-- 大批结果先分块暂存；摘要、条数、覆盖验证后，事务内发布快照并更新完整结果指针。
CREATE TABLE asset_inventory_snapshots (
    id uuid PRIMARY KEY,
    create_time timestamptz NOT NULL DEFAULT now(),
    update_time timestamptz NOT NULL DEFAULT now(),
    "delete" boolean NOT NULL DEFAULT false,
    collection_run_id uuid NOT NULL UNIQUE,
    asset_id uuid NOT NULL,
    collection_kind text NOT NULL DEFAULT 'inventory' CHECK (collection_kind = 'inventory'),
    hostname text,
    os_id text,
    os_version text,
    kernel_version text,
    architecture text,
    cpu_model text,
    logical_cpu_count integer CHECK (logical_cpu_count > 0),
    memory_total_bytes bigint CHECK (memory_total_bytes >= 0),
    boot_id uuid,
    booted_at timestamptz,
    interfaces jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(interfaces) = 'array'),
    filesystems jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(filesystems) = 'array'),
    FOREIGN KEY (collection_run_id, asset_id, collection_kind) REFERENCES collection_runs(id, asset_id, kind)
);
CREATE TABLE port_snapshot_endpoints (
    id uuid PRIMARY KEY,
    create_time timestamptz NOT NULL DEFAULT now(),
    update_time timestamptz NOT NULL DEFAULT now(),
    "delete" boolean NOT NULL DEFAULT false,
    collection_run_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    collection_kind text NOT NULL DEFAULT 'ports' CHECK (collection_kind = 'ports'),
    network_namespace text NOT NULL,
    protocol text NOT NULL CHECK (protocol IN ('tcp', 'udp')),
    local_address inet NOT NULL,
    address_scope text NOT NULL DEFAULT '',
    local_port integer NOT NULL CHECK (local_port BETWEEN 1 AND 65535),
    owners jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(owners) = 'array'),
    UNIQUE (collection_run_id, network_namespace, protocol, local_address, address_scope, local_port),
    FOREIGN KEY (collection_run_id, asset_id, collection_kind) REFERENCES collection_runs(id, asset_id, kind),
    CHECK (masklen(local_address) = CASE family(local_address) WHEN 4 THEN 32 ELSE 128 END)
);
-- 每行是去重后的 TCP 监听或 UDP 绑定端点；owners 有界，记录 PID+启动信息及截断标记。
-- IPv6 scope 单独保存；回环按 127.0.0.0/8 和 ::1 过滤，通配地址不能排除。
CREATE TABLE docker_port_mappings (
    id uuid PRIMARY KEY,
    create_time timestamptz NOT NULL DEFAULT now(),
    update_time timestamptz NOT NULL DEFAULT now(),
    "delete" boolean NOT NULL DEFAULT false,
    collection_run_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    collection_kind text NOT NULL DEFAULT 'ports' CHECK (collection_kind = 'ports'),
    container_id text NOT NULL,
    protocol text NOT NULL CHECK (protocol IN ('tcp', 'udp')),
    host_address inet NOT NULL,
    host_port integer NOT NULL CHECK (host_port BETWEEN 1 AND 65535),
    container_port integer NOT NULL CHECK (container_port BETWEEN 1 AND 65535),
    UNIQUE (collection_run_id, container_id, protocol, host_address, host_port, container_port),
    FOREIGN KEY (collection_run_id, asset_id, collection_kind) REFERENCES collection_runs(id, asset_id, kind),
    CHECK (masklen(host_address) = CASE family(host_address) WHEN 4 THEN 32 ELSE 128 END)
);
CREATE TABLE asset_collection_heads (
    id uuid PRIMARY KEY,
    create_time timestamptz NOT NULL DEFAULT now(),
    update_time timestamptz NOT NULL DEFAULT now(),
    "delete" boolean NOT NULL DEFAULT false,
    asset_id uuid NOT NULL REFERENCES assets(id),
    kind text NOT NULL,
    scope_key text NOT NULL,
    latest_attempt_id uuid NOT NULL,
    latest_complete_id uuid,
    UNIQUE (asset_id, kind, scope_key),
    FOREIGN KEY (latest_attempt_id, asset_id, kind, scope_key) REFERENCES collection_runs(id, asset_id, kind, scope_key),
    FOREIGN KEY (latest_complete_id, asset_id, kind, scope_key) REFERENCES collection_runs(id, asset_id, kind, scope_key)
);
-- 最近尝试与最近完整结果分别比较安装 generation/sequence，不能共用一个接收时间水位。
-- FK 不检查 complete 状态；接纳身份、状态、覆盖和顺序须在锁定 head 的事务中验证。

CREATE TABLE asset_metric_latest (
    id uuid PRIMARY KEY,
    create_time timestamptz NOT NULL DEFAULT now(),
    update_time timestamptz NOT NULL DEFAULT now(),
    "delete" boolean NOT NULL DEFAULT false,
    asset_id uuid NOT NULL UNIQUE REFERENCES assets(id),
    installation_id uuid NOT NULL,
    instance_id uuid NOT NULL,
    active_epoch bigint NOT NULL CHECK (active_epoch > 0),
    sequence bigint NOT NULL CHECK (sequence >= 0),
    boot_id uuid NOT NULL,
    observed_at timestamptz NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now(),
    cpu_percent numeric(6,3) CHECK (cpu_percent BETWEEN 0 AND 100),
    memory_total_bytes bigint CHECK (memory_total_bytes >= 0),
    memory_available_bytes bigint CHECK (memory_available_bytes >= 0),
    process_count integer CHECK (process_count >= 0),
    running_process_count integer CHECK (running_process_count >= 0),
    zombie_process_count integer CHECK (zombie_process_count >= 0),
    load1 double precision CHECK (load1 >= 0 AND load1 < 'Infinity'::float8),
    swap_used_bytes bigint CHECK (swap_used_bytes >= 0),
    resource_summary jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(resource_summary) = 'object'),
    scout_health jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(scout_health) = 'object'),
    quality jsonb NOT NULL CHECK (jsonb_typeof(quality) = 'object'),
    FOREIGN KEY (instance_id, asset_id, installation_id) REFERENCES scout_instances(id, asset_id, installation_id),
    CHECK (memory_available_bytes <= memory_total_bytes)
);
CREATE INDEX asset_metric_latest_seen_idx ON asset_metric_latest(received_at);
-- 当前状态仅一行/资产；指标 sequence 是独立于 collection_runs 的本地持久序列。
-- resource_summary 仅最近一批网卡/磁盘摘要，限制条数；不在 JSON 中累积时间序列。

-- 指标使用普通表，以满足每表 id 单列主键规范；业务桶维度另保留全局 UNIQUE。
-- 时间范围索引用于查询与分批保留清理；不再使用无法支持该单列主键的时间分区。
CREATE TABLE host_metric_buckets (
    id uuid PRIMARY KEY,
    create_time timestamptz NOT NULL DEFAULT now(),
    update_time timestamptz NOT NULL DEFAULT now(),
    "delete" boolean NOT NULL DEFAULT false,
    asset_id uuid NOT NULL REFERENCES assets(id),
    installation_id uuid NOT NULL,
    instance_id uuid NOT NULL,
    active_epoch bigint NOT NULL CHECK (active_epoch > 0),
    resolution_seconds integer NOT NULL CHECK (resolution_seconds IN (60, 3600)),
    bucket_start timestamptz NOT NULL,
    observed_from timestamptz NOT NULL,
    observed_until timestamptz NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    sample_count integer NOT NULL CHECK (sample_count > 0),
    cpu_percent_seconds_sum numeric(20,6) NOT NULL CHECK (cpu_percent_seconds_sum >= 0),
    cpu_observed_seconds numeric(12,6) NOT NULL CHECK (cpu_observed_seconds BETWEEN 0 AND resolution_seconds),
    cpu_percent_max numeric(6,3) CHECK (cpu_percent_max BETWEEN 0 AND 100),
    memory_used_byte_seconds numeric(40,6) NOT NULL CHECK (memory_used_byte_seconds >= 0 AND memory_used_byte_seconds < 'Infinity'::numeric),
    memory_observed_seconds numeric(12,6) NOT NULL CHECK (memory_observed_seconds BETWEEN 0 AND resolution_seconds),
    memory_used_bytes_max bigint CHECK (memory_used_bytes_max >= 0),
    memory_total_bytes_last bigint CHECK (memory_total_bytes_last >= 0),
    process_count_max integer CHECK (process_count_max >= 0),
    process_count_last integer CHECK (process_count_last >= 0),
    load1_max double precision CHECK (load1_max >= 0 AND load1_max < 'Infinity'::float8),
    swap_used_bytes_max bigint CHECK (swap_used_bytes_max >= 0),
    quality jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(quality) = 'object'),
    UNIQUE (asset_id, resolution_seconds, bucket_start, installation_id, active_epoch),
    FOREIGN KEY (instance_id, asset_id, installation_id) REFERENCES scout_instances(id, asset_id, installation_id),
    CHECK (mod(extract(epoch FROM bucket_start), resolution_seconds) = 0),
    CHECK (bucket_start <= observed_from AND observed_from < observed_until
        AND observed_until <= bucket_start + resolution_seconds * interval '1 second'),
    CHECK (cpu_observed_seconds <= extract(epoch FROM observed_until - observed_from)),
    CHECK (memory_observed_seconds <= extract(epoch FROM observed_until - observed_from)),
    CHECK (cpu_percent_seconds_sum <= 100 * cpu_observed_seconds),
    CHECK ((cpu_observed_seconds = 0 AND cpu_percent_max IS NULL) OR
           (cpu_observed_seconds > 0 AND cpu_percent_max IS NOT NULL)),
    CHECK ((memory_observed_seconds = 0 AND memory_used_byte_seconds = 0 AND memory_used_bytes_max IS NULL) OR
           (memory_observed_seconds > 0 AND memory_used_bytes_max IS NOT NULL))
);
CREATE INDEX host_metric_buckets_retention_idx ON host_metric_buckets(resolution_seconds, bucket_start, id);

CREATE TABLE network_metric_buckets (
    id uuid PRIMARY KEY,
    create_time timestamptz NOT NULL DEFAULT now(),
    update_time timestamptz NOT NULL DEFAULT now(),
    "delete" boolean NOT NULL DEFAULT false,
    asset_id uuid NOT NULL REFERENCES assets(id),
    installation_id uuid NOT NULL,
    instance_id uuid NOT NULL,
    active_epoch bigint NOT NULL CHECK (active_epoch > 0),
    resolution_seconds integer NOT NULL CHECK (resolution_seconds IN (60, 3600)),
    bucket_start timestamptz NOT NULL,
    observed_from timestamptz NOT NULL,
    observed_until timestamptz NOT NULL,
    resource_key text NOT NULL CHECK (resource_key <> ''),
    interface_name text NOT NULL,
    interface_kind text NOT NULL CHECK (interface_kind IN ('physical', 'bridge', 'virtual', 'loopback', 'unknown')),
    revision bigint NOT NULL CHECK (revision > 0),
    sample_count integer NOT NULL CHECK (sample_count > 0),
    observed_seconds numeric(12,6) NOT NULL CHECK (observed_seconds BETWEEN 0 AND resolution_seconds),
    rx_bytes_delta numeric(30,0) CHECK (rx_bytes_delta >= 0 AND rx_bytes_delta < 'Infinity'::numeric),
    tx_bytes_delta numeric(30,0) CHECK (tx_bytes_delta >= 0 AND tx_bytes_delta < 'Infinity'::numeric),
    rx_bytes_per_second_max numeric(30,6) CHECK (rx_bytes_per_second_max >= 0 AND rx_bytes_per_second_max < 'Infinity'::numeric),
    tx_bytes_per_second_max numeric(30,6) CHECK (tx_bytes_per_second_max >= 0 AND tx_bytes_per_second_max < 'Infinity'::numeric),
    error_count_delta numeric(30,0) CHECK (error_count_delta >= 0 AND error_count_delta < 'Infinity'::numeric),
    dropped_count_delta numeric(30,0) CHECK (dropped_count_delta >= 0 AND dropped_count_delta < 'Infinity'::numeric),
    quality jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(quality) = 'object'),
    UNIQUE (asset_id, resolution_seconds, bucket_start, resource_key, installation_id, active_epoch),
    FOREIGN KEY (instance_id, asset_id, installation_id) REFERENCES scout_instances(id, asset_id, installation_id),
    CHECK (mod(extract(epoch FROM bucket_start), resolution_seconds) = 0),
    CHECK (bucket_start <= observed_from AND observed_from < observed_until
        AND observed_until <= bucket_start + resolution_seconds * interval '1 second'),
    CHECK (observed_seconds <= extract(epoch FROM observed_until - observed_from)),
    CHECK ((observed_seconds = 0 AND rx_bytes_delta IS NULL AND tx_bytes_delta IS NULL) OR
           (observed_seconds > 0 AND rx_bytes_delta IS NOT NULL AND tx_bytes_delta IS NOT NULL))
);
CREATE INDEX network_metric_buckets_retention_idx ON network_metric_buckets(resolution_seconds, bucket_start, id);
-- resource_key 包含 boot/接口实例标识，不能只用 eth0；速率按有效计数差/有效时长计算。
CREATE TABLE filesystem_metric_buckets (
    id uuid PRIMARY KEY,
    create_time timestamptz NOT NULL DEFAULT now(),
    update_time timestamptz NOT NULL DEFAULT now(),
    "delete" boolean NOT NULL DEFAULT false,
    asset_id uuid NOT NULL REFERENCES assets(id),
    installation_id uuid NOT NULL,
    instance_id uuid NOT NULL,
    active_epoch bigint NOT NULL CHECK (active_epoch > 0),
    resolution_seconds integer NOT NULL CHECK (resolution_seconds IN (60, 3600)),
    bucket_start timestamptz NOT NULL,
    observed_from timestamptz NOT NULL,
    observed_until timestamptz NOT NULL,
    resource_key text NOT NULL CHECK (resource_key <> ''),
    mount_point text NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    sample_count integer NOT NULL CHECK (sample_count > 0),
    observed_seconds numeric(12,6) NOT NULL CHECK (observed_seconds BETWEEN 0 AND resolution_seconds),
    total_bytes_last bigint CHECK (total_bytes_last >= 0),
    available_bytes_last bigint CHECK (available_bytes_last >= 0),
    used_bytes_max bigint CHECK (used_bytes_max >= 0),
    inode_available_min bigint CHECK (inode_available_min >= 0),
    quality jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(quality) = 'object'),
    UNIQUE (asset_id, resolution_seconds, bucket_start, resource_key, installation_id, active_epoch),
    FOREIGN KEY (instance_id, asset_id, installation_id) REFERENCES scout_instances(id, asset_id, installation_id),
    CHECK (mod(extract(epoch FROM bucket_start), resolution_seconds) = 0),
    CHECK (bucket_start <= observed_from AND observed_from < observed_until
        AND observed_until <= bucket_start + resolution_seconds * interval '1 second'),
    CHECK (observed_seconds <= extract(epoch FROM observed_until - observed_from)),
    CHECK (available_bytes_last <= total_bytes_last)
);
CREATE INDEX filesystem_metric_buckets_retention_idx ON filesystem_metric_buckets(resolution_seconds, bucket_start, id);
-- 小时聚合对加权和/有效时长分别求和，max 求最大，last 取最新有效值；不可直接平均分钟平均数。
-- 每个安装身份/active_epoch 独占一段；实例切换、重启接管和回滚恢复均提升 epoch。
-- 本地活动锁、持久交接记录和 Hub 认证准入验证段归属；上述 FK 不保证 epoch 的合法所有者。
-- 分钟与小时桶都保留分段键，查询按资产/时间桶合并有效段，不跨段比较 revision。
-- 每段每桶保存完整累计值；分钟 revision 由 Scout 持久递增，小时 revision 由 Hub 聚合事务递增。
-- Hub 仅接纳较新的分钟 revision，不盲目累加重投；不同桶的 revision 不相互比较。
-- 小时桶合并同段多个分钟；from/until 是包围范围，范围内允许缺测，秒数字段仅累计有效覆盖。
-- 应用在锁定同资产桶的事务中检查各段有效覆盖不重叠、总时长不超过桶长，不能只依赖行内 CHECK。
-- 小时更正须从已接纳分钟贡献重新聚合，按同段更新 revision；不得把重传再次计入小时累计。
-- 正式实现需校验所有数值为有限值、资源配额、时间偏差及桶覆盖，不依赖 CHECK 替代输入验证。
-- "delete" 是软删除标记，普通读取显式过滤 NOT "delete"；外键不验证目标未软删。
-- 身份必须先吊销/退出，资产必须先退役；软删除不得用于绕开认证、运行互斥或采集状态。
-- 不可变快照/结果的业务去重键跨软删保留；使用原记录的专门恢复流程，不另建重复事实。
CREATE TRIGGER asset_groups_metadata_before_update
    BEFORE UPDATE ON asset_groups
    FOR EACH ROW EXECUTE FUNCTION sentinel.set_row_metadata();
CREATE TRIGGER assets_metadata_before_update
    BEFORE UPDATE ON assets
    FOR EACH ROW EXECUTE FUNCTION sentinel.set_row_metadata();
CREATE TRIGGER asset_tags_metadata_before_update
    BEFORE UPDATE ON asset_tags
    FOR EACH ROW EXECUTE FUNCTION sentinel.set_row_metadata();
CREATE TRIGGER scout_installations_metadata_before_update
    BEFORE UPDATE ON scout_installations
    FOR EACH ROW EXECUTE FUNCTION sentinel.set_row_metadata();
CREATE TRIGGER scout_credentials_metadata_before_update
    BEFORE UPDATE ON scout_credentials
    FOR EACH ROW EXECUTE FUNCTION sentinel.set_row_metadata();
CREATE TRIGGER scout_instances_metadata_before_update
    BEFORE UPDATE ON scout_instances
    FOR EACH ROW EXECUTE FUNCTION sentinel.set_row_metadata();
CREATE TRIGGER asset_fingerprint_observations_metadata_before_update
    BEFORE UPDATE ON asset_fingerprint_observations
    FOR EACH ROW EXECUTE FUNCTION sentinel.set_row_metadata();
CREATE TRIGGER identity_conflicts_metadata_before_update
    BEFORE UPDATE ON identity_conflicts
    FOR EACH ROW EXECUTE FUNCTION sentinel.set_row_metadata();
CREATE TRIGGER package_snapshots_metadata_before_update
    BEFORE UPDATE ON package_snapshots
    FOR EACH ROW EXECUTE FUNCTION sentinel.set_row_metadata();
CREATE TRIGGER package_entries_metadata_before_update
    BEFORE UPDATE ON package_entries
    FOR EACH ROW EXECUTE FUNCTION sentinel.set_row_metadata();
CREATE TRIGGER collection_runs_metadata_before_update
    BEFORE UPDATE ON collection_runs
    FOR EACH ROW EXECUTE FUNCTION sentinel.set_row_metadata();
CREATE TRIGGER asset_inventory_snapshots_metadata_before_update
    BEFORE UPDATE ON asset_inventory_snapshots
    FOR EACH ROW EXECUTE FUNCTION sentinel.set_row_metadata();
CREATE TRIGGER port_snapshot_endpoints_metadata_before_update
    BEFORE UPDATE ON port_snapshot_endpoints
    FOR EACH ROW EXECUTE FUNCTION sentinel.set_row_metadata();
CREATE TRIGGER docker_port_mappings_metadata_before_update
    BEFORE UPDATE ON docker_port_mappings
    FOR EACH ROW EXECUTE FUNCTION sentinel.set_row_metadata();
CREATE TRIGGER asset_collection_heads_metadata_before_update
    BEFORE UPDATE ON asset_collection_heads
    FOR EACH ROW EXECUTE FUNCTION sentinel.set_row_metadata();
CREATE TRIGGER asset_metric_latest_metadata_before_update
    BEFORE UPDATE ON asset_metric_latest
    FOR EACH ROW EXECUTE FUNCTION sentinel.set_row_metadata();
CREATE TRIGGER host_metric_buckets_metadata_before_update
    BEFORE UPDATE ON host_metric_buckets
    FOR EACH ROW EXECUTE FUNCTION sentinel.set_row_metadata();
CREATE TRIGGER network_metric_buckets_metadata_before_update
    BEFORE UPDATE ON network_metric_buckets
    FOR EACH ROW EXECUTE FUNCTION sentinel.set_row_metadata();
CREATE TRIGGER filesystem_metric_buckets_metadata_before_update
    BEFORE UPDATE ON filesystem_metric_buckets
    FOR EACH ROW EXECUTE FUNCTION sentinel.set_row_metadata();
