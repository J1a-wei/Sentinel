-- 设计草案：Ubuntu 漏洞评估、配置基线与当前风险。依赖 001。
-- UUID 由应用分配；原始密码、密码散列和完整配置文件不得进入证据字段。
-- 每表统一 id/create_time/update_time/"delete"；"delete" 必须加双引号引用。
-- 普通查询过滤 NOT "delete"；软删除不释放结果/修订/历史的业务唯一键，也不代表风险修复。
BEGIN;
SET LOCAL search_path = sentinel, pg_catalog;

CREATE TABLE vulnerability_intelligence_revisions (
    id uuid PRIMARY KEY,
    create_time timestamptz NOT NULL DEFAULT now(),
    update_time timestamptz NOT NULL DEFAULT now(),
    "delete" boolean NOT NULL DEFAULT false,
    source_key text NOT NULL CHECK (source_key <> ''),
    upstream_revision text NOT NULL CHECK (upstream_revision <> ''),
    content_sha256 text NOT NULL CHECK (content_sha256 ~ '^[0-9a-f]{64}$'),
    status text NOT NULL CHECK (status IN ('importing', 'ready', 'failed')),
    published_at timestamptz,
    retrieved_at timestamptz NOT NULL,
    last_checked_at timestamptz NOT NULL,
    ready_at timestamptz,
    error_code text,
    UNIQUE (source_key, content_sha256),
    CHECK ((status = 'ready') = (ready_at IS NOT NULL)),
    CHECK (last_checked_at >= retrieved_at)
);

-- 架构集合为空且 scope=all 表示适用于所有架构；selected 表示明确枚举。
-- ready 后情报正文与 advisory 不可修改；修正数据创建新修订。状态/检查时间例外。
-- 版本保留完整 Debian 字符串，由经过验证的比较器解释，不使用文本大小比较。
CREATE TABLE ubuntu_package_advisories (
    id uuid PRIMARY KEY,
    create_time timestamptz NOT NULL DEFAULT now(),
    update_time timestamptz NOT NULL DEFAULT now(),
    "delete" boolean NOT NULL DEFAULT false,
    intelligence_revision_id uuid NOT NULL REFERENCES vulnerability_intelligence_revisions (id),
    cve_id text NOT NULL CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
    ubuntu_release text NOT NULL CHECK (ubuntu_release <> ''),
    source_name text NOT NULL CHECK (source_name <> ''),
    architecture_scope text NOT NULL CHECK (architecture_scope IN ('all', 'selected')),
    architectures text[] NOT NULL DEFAULT '{}',
    upstream_status text NOT NULL CHECK (upstream_status <> ''),
    verdict text NOT NULL CHECK (verdict IN (
        'affected_fix_available', 'affected_no_fix', 'needs_triage', 'not_affected', 'unknown'
    )),
    fixed_version text CHECK (fixed_version <> ''),
    severity text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info', 'unknown')),
    source_severity text,
    reference_url text NOT NULL CHECK (reference_url <> ''),
    source_record jsonb NOT NULL CHECK (jsonb_typeof(source_record) = 'object'),
    UNIQUE (id, intelligence_revision_id, cve_id),
    UNIQUE (intelligence_revision_id, cve_id, ubuntu_release, source_name, architecture_scope, architectures),
    CHECK (array_position(architectures, NULL) IS NULL),
    CHECK ((architecture_scope = 'all' AND cardinality(architectures) = 0)
        OR (architecture_scope = 'selected' AND cardinality(architectures) > 0)),
    CHECK (verdict <> 'affected_fix_available' OR fixed_version IS NOT NULL)
);
CREATE INDEX ubuntu_advisories_match_idx ON ubuntu_package_advisories
    (intelligence_revision_id, ubuntu_release, source_name);
-- 导入器校验同一 CVE/发行版/源包的架构适用集不重叠；不能仅靠数组唯一索引保证。
-- 架构列表须排序、去重并校验非空元素；source_record 仅保留有界的公开情报记录。

-- 同一清单可按新版情报或匹配器重评估；不覆盖原评估结果。
-- 排队和执行中的评估不能软删除；取消须先走任务状态转换并记录结束时间。
CREATE TABLE vulnerability_evaluation_runs (
    id uuid PRIMARY KEY,
    create_time timestamptz NOT NULL DEFAULT now(),
    update_time timestamptz NOT NULL DEFAULT now(),
    "delete" boolean NOT NULL DEFAULT false,
    asset_id uuid NOT NULL REFERENCES assets (id),
    snapshot_id uuid NOT NULL,
    intelligence_revision_id uuid NOT NULL REFERENCES vulnerability_intelligence_revisions (id),
    matcher_revision text NOT NULL CHECK (matcher_revision <> ''),
    status text NOT NULL CHECK (status IN ('queued', 'running', 'complete', 'partial', 'failed', 'cancelled')),
    requested_at timestamptz NOT NULL,
    started_at timestamptz,
    finished_at timestamptz,
    error_code text,
    UNIQUE (id, asset_id),
    UNIQUE (id, snapshot_id),
    UNIQUE (id, asset_id, intelligence_revision_id),
    FOREIGN KEY (snapshot_id, asset_id) REFERENCES package_snapshots (id, asset_id),
    CHECK (started_at IS NULL OR started_at >= requested_at),
    CHECK (finished_at IS NULL OR finished_at >= COALESCE(started_at, requested_at)),
    CHECK (status NOT IN ('running', 'complete', 'partial') OR started_at IS NOT NULL),
    CHECK (status <> 'queued' OR started_at IS NULL),
    CHECK (NOT "delete" OR status NOT IN ('queued', 'running')),
    CHECK ((status IN ('complete', 'partial', 'failed', 'cancelled')) = (finished_at IS NOT NULL))
);
CREATE INDEX vulnerability_evaluations_asset_idx ON vulnerability_evaluation_runs (asset_id, requested_at DESC);
CREATE INDEX vulnerability_evaluations_input_idx ON vulnerability_evaluation_runs
    (snapshot_id, intelligence_revision_id, matcher_revision);

-- 每次评估对每个清单包记录覆盖情况；assessed 表示匹配完成，不代表已验证运行代码。
-- 不生成“每个包 × 全部 CVE”的正常结果矩阵；没有命中且没有覆盖记录不能判为安全。
CREATE TABLE vulnerability_package_coverage (
    id uuid PRIMARY KEY,
    create_time timestamptz NOT NULL DEFAULT now(),
    update_time timestamptz NOT NULL DEFAULT now(),
    "delete" boolean NOT NULL DEFAULT false,
    evaluation_id uuid NOT NULL,
    snapshot_id uuid NOT NULL,
    package_name text NOT NULL,
    architecture text NOT NULL,
    status text NOT NULL CHECK (status IN ('assessed', 'unknown_origin', 'unsupported', 'error', 'unknown')),
    reason_code text,
    UNIQUE (evaluation_id, package_name, architecture),
    FOREIGN KEY (evaluation_id, snapshot_id) REFERENCES vulnerability_evaluation_runs (id, snapshot_id),
    FOREIGN KEY (snapshot_id, package_name, architecture)
        REFERENCES package_entries (snapshot_id, package_name, architecture),
    CHECK (status = 'assessed' OR reason_code IS NOT NULL)
);

-- 仅保存匹配候选及复查所需的明确结论；unknown/needs_triage 不是已确认漏洞。
-- 包版本从绑定的不可变清单读取；修复版本和严重性固化本次评估解释。
CREATE TABLE vulnerability_results (
    id uuid PRIMARY KEY,
    create_time timestamptz NOT NULL DEFAULT now(),
    update_time timestamptz NOT NULL DEFAULT now(),
    "delete" boolean NOT NULL DEFAULT false,
    evaluation_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    intelligence_revision_id uuid NOT NULL,
    package_name text NOT NULL,
    architecture text NOT NULL,
    cve_id text NOT NULL,
    advisory_id uuid NOT NULL,
    verdict text NOT NULL CHECK (verdict IN (
        'affected_fix_available', 'affected_no_fix', 'needs_triage', 'not_affected', 'unknown'
    )),
    fixed_version text CHECK (fixed_version <> ''),
    severity text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info', 'unknown')),
    reason_code text NOT NULL CHECK (reason_code <> ''),
    evidence jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(evidence) = 'object'),
    evaluated_at timestamptz NOT NULL,
    UNIQUE (id, asset_id),
    UNIQUE (evaluation_id, package_name, architecture, cve_id),
    FOREIGN KEY (evaluation_id, asset_id, intelligence_revision_id)
        REFERENCES vulnerability_evaluation_runs (id, asset_id, intelligence_revision_id),
    FOREIGN KEY (evaluation_id, package_name, architecture)
        REFERENCES vulnerability_package_coverage (evaluation_id, package_name, architecture),
    FOREIGN KEY (advisory_id, intelligence_revision_id, cve_id)
        REFERENCES ubuntu_package_advisories (id, intelligence_revision_id, cve_id),
    CHECK (verdict <> 'affected_fix_available' OR fixed_version IS NOT NULL)
);
CREATE INDEX vulnerability_results_asset_idx ON vulnerability_results (asset_id, evaluated_at DESC);
CREATE INDEX vulnerability_results_cve_idx ON vulnerability_results (cve_id, asset_id);

-- 最近尝试与最近完整评估分开；失败不得把仍存在的旧风险清空。
-- 指针推进须对比当前完整清单、目标情报版本及匹配器版本，不按消息到达顺序覆盖。
CREATE TABLE asset_vulnerability_heads (
    id uuid PRIMARY KEY,
    create_time timestamptz NOT NULL DEFAULT now(),
    update_time timestamptz NOT NULL DEFAULT now(),
    "delete" boolean NOT NULL DEFAULT false,
    asset_id uuid NOT NULL UNIQUE REFERENCES assets (id),
    latest_attempt_id uuid NOT NULL,
    latest_complete_id uuid,
    FOREIGN KEY (latest_attempt_id, asset_id) REFERENCES vulnerability_evaluation_runs (id, asset_id),
    FOREIGN KEY (latest_complete_id, asset_id) REFERENCES vulnerability_evaluation_runs (id, asset_id)
);

CREATE TABLE baseline_rule_revisions (
    id uuid PRIMARY KEY,
    create_time timestamptz NOT NULL DEFAULT now(),
    update_time timestamptz NOT NULL DEFAULT now(),
    "delete" boolean NOT NULL DEFAULT false,
    rule_key text NOT NULL CHECK (rule_key <> ''),
    revision integer NOT NULL CHECK (revision > 0),
    title text NOT NULL CHECK (title <> ''),
    severity text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info', 'unknown')),
    applicable_scope jsonb NOT NULL CHECK (jsonb_typeof(applicable_scope) = 'object'),
    specification jsonb NOT NULL CHECK (jsonb_typeof(specification) = 'object'),
    remediation text NOT NULL,
    content_sha256 text NOT NULL CHECK (content_sha256 ~ '^[0-9a-f]{64}$'),
    UNIQUE (rule_key, revision),
    UNIQUE (id, rule_key)
);

-- 复用 collection_runs；不另外维护一次基线检查的平行状态机。
-- context_key 是规范化检查范围摘要，区分 SSH Match 用户/地址等上下文。
-- collection_runs 的策略/规则清单及覆盖元数据须保留预期检查范围；缺失结果不等于通过。
CREATE TABLE baseline_results (
    id uuid PRIMARY KEY,
    create_time timestamptz NOT NULL DEFAULT now(),
    update_time timestamptz NOT NULL DEFAULT now(),
    "delete" boolean NOT NULL DEFAULT false,
    collection_run_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    collection_kind text NOT NULL DEFAULT 'baseline' CHECK (collection_kind = 'baseline'),
    rule_revision_id uuid NOT NULL,
    rule_key text NOT NULL,
    context_key text NOT NULL CHECK (context_key <> ''),
    context_summary jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(context_summary) = 'object'),
    verdict text NOT NULL CHECK (verdict IN ('pass', 'fail', 'unknown', 'error', 'not_applicable', 'not_run')),
    configuration_view text NOT NULL CHECK (configuration_view IN ('disk', 'running', 'mixed', 'unknown')),
    runtime_confirmation text NOT NULL CHECK (runtime_confirmation IN ('confirmed', 'unconfirmed', 'not_applicable')),
    reason_code text,
    evidence jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(evidence) = 'object'),
    evaluated_at timestamptz NOT NULL,
    UNIQUE (id, asset_id),
    UNIQUE (collection_run_id, rule_key, context_key),
    FOREIGN KEY (collection_run_id, asset_id, collection_kind)
        REFERENCES collection_runs (id, asset_id, kind),
    FOREIGN KEY (rule_revision_id, rule_key) REFERENCES baseline_rule_revisions (id, rule_key),
    CHECK (verdict IN ('pass', 'fail') OR reason_code IS NOT NULL)
);
CREATE INDEX baseline_results_asset_idx ON baseline_results (asset_id, evaluated_at DESC);
CREATE INDEX baseline_results_rule_idx ON baseline_results (rule_key, verdict, asset_id);

-- findings 仅为风险当前投影；权威事实仍在领域结果表。不是所有 pass/error 都建 finding。
-- finding_key 不含包版本、扫描时间、规则修订；应用按域规范化稳定问题身份。
-- 漏洞键含发行版范围/CVE/二进制包/架构；基线键含 rule_key/context_key。
CREATE TABLE findings (
    id uuid PRIMARY KEY,
    create_time timestamptz NOT NULL DEFAULT now(),
    update_time timestamptz NOT NULL DEFAULT now(),
    "delete" boolean NOT NULL DEFAULT false,
    asset_id uuid NOT NULL REFERENCES assets (id),
    kind text NOT NULL CHECK (kind IN ('vulnerability', 'baseline')),
    finding_key text NOT NULL CHECK (finding_key <> ''),
    technical_state text NOT NULL CHECK (technical_state IN ('present', 'resolved', 'unknown')),
    disposition text NOT NULL DEFAULT 'open' CHECK (disposition IN ('open', 'acknowledged', 'accepted_risk', 'false_positive')),
    disposition_reason text,
    disposition_expires_at timestamptz,
    severity text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info', 'unknown')),
    first_seen_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL,
    last_evaluated_at timestamptz NOT NULL,
    resolved_at timestamptz,
    vulnerability_result_id uuid,
    baseline_result_id uuid,
    closure_evaluation_id uuid,
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    UNIQUE (asset_id, kind, finding_key),
    UNIQUE (id, asset_id),
    UNIQUE (id, asset_id, kind),
    FOREIGN KEY (vulnerability_result_id, asset_id) REFERENCES vulnerability_results (id, asset_id),
    FOREIGN KEY (baseline_result_id, asset_id) REFERENCES baseline_results (id, asset_id),
    FOREIGN KEY (closure_evaluation_id, asset_id) REFERENCES vulnerability_evaluation_runs (id, asset_id),
    CHECK ((kind = 'vulnerability' AND vulnerability_result_id IS NOT NULL AND baseline_result_id IS NULL)
        OR (kind = 'baseline' AND baseline_result_id IS NOT NULL AND vulnerability_result_id IS NULL)),
    CHECK (last_seen_at >= first_seen_at),
    CHECK ((technical_state = 'resolved') = (resolved_at IS NOT NULL)),
    CHECK (closure_evaluation_id IS NULL OR (kind = 'vulnerability' AND technical_state = 'resolved')),
    CHECK (disposition NOT IN ('accepted_risk', 'false_positive') OR disposition_reason IS NOT NULL)
);
CREATE INDEX findings_asset_state_idx ON findings (asset_id, technical_state, severity);
CREATE INDEX findings_open_idx ON findings (severity, last_seen_at DESC) WHERE technical_state = 'present' AND NOT "delete";

-- 更新投影与追加状态历史须在同一事务中，并检查 version 防止并发覆盖。
-- 只有完整、适用、成功且足够新鲜的评估可关闭风险；缺失结果/包/权限均不可独立证明修复。
-- 若包在新的完整清单中被卸载，可引用关闭依据的 evaluation_id；不是伪造漏洞匹配结果。
CREATE TABLE finding_state_changes (
    id uuid PRIMARY KEY,
    create_time timestamptz NOT NULL DEFAULT now(),
    update_time timestamptz NOT NULL DEFAULT now(),
    "delete" boolean NOT NULL DEFAULT false,
    finding_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    kind text NOT NULL CHECK (kind IN ('vulnerability', 'baseline')),
    finding_version bigint NOT NULL CHECK (finding_version > 0),
    change_type text NOT NULL CHECK (change_type IN ('created', 'assessment', 'disposition')),
    previous_technical_state text CHECK (previous_technical_state IN ('present', 'resolved', 'unknown')),
    technical_state text NOT NULL CHECK (technical_state IN ('present', 'resolved', 'unknown')),
    previous_disposition text CHECK (previous_disposition IN ('open', 'acknowledged', 'accepted_risk', 'false_positive')),
    disposition text NOT NULL CHECK (disposition IN ('open', 'acknowledged', 'accepted_risk', 'false_positive')),
    vulnerability_result_id uuid,
    baseline_result_id uuid,
    closure_evaluation_id uuid,
    actor_kind text NOT NULL CHECK (actor_kind IN ('system', 'user')),
    actor_reference text NOT NULL CHECK (actor_reference <> ''),
    reason_code text NOT NULL CHECK (reason_code <> ''),
    changed_at timestamptz NOT NULL,
    UNIQUE (finding_id, finding_version),
    FOREIGN KEY (finding_id, asset_id, kind) REFERENCES findings (id, asset_id, kind),
    FOREIGN KEY (vulnerability_result_id, asset_id) REFERENCES vulnerability_results (id, asset_id),
    FOREIGN KEY (baseline_result_id, asset_id) REFERENCES baseline_results (id, asset_id),
    FOREIGN KEY (closure_evaluation_id, asset_id) REFERENCES vulnerability_evaluation_runs (id, asset_id),
    CHECK ((kind = 'vulnerability' AND baseline_result_id IS NULL)
        OR (kind = 'baseline' AND vulnerability_result_id IS NULL AND closure_evaluation_id IS NULL)),
    CHECK (change_type <> 'created' OR (previous_technical_state IS NULL AND previous_disposition IS NULL)),
    CHECK (change_type = 'created' OR (previous_technical_state IS NOT NULL AND previous_disposition IS NOT NULL)),
    CHECK (change_type <> 'disposition' OR actor_kind = 'user'),
    CHECK (change_type <> 'disposition' OR previous_technical_state = technical_state),
    CHECK (change_type <> 'assessment' OR previous_disposition = disposition),
    CHECK (change_type = 'disposition'
        OR (kind = 'vulnerability' AND (vulnerability_result_id IS NOT NULL OR closure_evaluation_id IS NOT NULL))
        OR (kind = 'baseline' AND baseline_result_id IS NOT NULL)),
    CHECK (closure_evaluation_id IS NULL OR (kind = 'vulnerability' AND technical_state = 'resolved'))
);
CREATE INDEX finding_changes_asset_time_idx ON finding_state_changes (asset_id, changed_at DESC);

-- 完成度、情报 ready、身份一致性之外的适用性、版本比较与状态转换由应用事务验证。
-- 不可变快照/结果/修订/历史由写入权限和应用约束保护；DDL 未声称自动实施所有规则。
-- actor_reference 是审计时的认证主体标识快照，不用于鉴权；跨表关联须按同资产范围验证。
-- 结果及评估不得在仍被 findings/历史引用时直接清理；保留策略需先处理证据依赖。
-- 外键仍可指向软删除行；应用写入事务须验证依赖可用，并保护审计/证据可追溯性。
-- 软删除 findings 不改变 technical_state/disposition；再次发现同一问题须恢复原投影，不能绕过去重。
-- 下列触发器仅维护基础元数据；软删除权限、状态转换与正文不可变性仍由业务事务和权限落实。
CREATE TRIGGER vulnerability_intelligence_revisions_metadata
    BEFORE UPDATE ON vulnerability_intelligence_revisions
    FOR EACH ROW EXECUTE FUNCTION sentinel.set_row_metadata();
CREATE TRIGGER ubuntu_package_advisories_metadata
    BEFORE UPDATE ON ubuntu_package_advisories
    FOR EACH ROW EXECUTE FUNCTION sentinel.set_row_metadata();
CREATE TRIGGER vulnerability_evaluation_runs_metadata
    BEFORE UPDATE ON vulnerability_evaluation_runs
    FOR EACH ROW EXECUTE FUNCTION sentinel.set_row_metadata();
CREATE TRIGGER vulnerability_package_coverage_metadata
    BEFORE UPDATE ON vulnerability_package_coverage
    FOR EACH ROW EXECUTE FUNCTION sentinel.set_row_metadata();
CREATE TRIGGER vulnerability_results_metadata
    BEFORE UPDATE ON vulnerability_results
    FOR EACH ROW EXECUTE FUNCTION sentinel.set_row_metadata();
CREATE TRIGGER asset_vulnerability_heads_metadata
    BEFORE UPDATE ON asset_vulnerability_heads
    FOR EACH ROW EXECUTE FUNCTION sentinel.set_row_metadata();
CREATE TRIGGER baseline_rule_revisions_metadata
    BEFORE UPDATE ON baseline_rule_revisions
    FOR EACH ROW EXECUTE FUNCTION sentinel.set_row_metadata();
CREATE TRIGGER baseline_results_metadata
    BEFORE UPDATE ON baseline_results
    FOR EACH ROW EXECUTE FUNCTION sentinel.set_row_metadata();
CREATE TRIGGER findings_metadata
    BEFORE UPDATE ON findings
    FOR EACH ROW EXECUTE FUNCTION sentinel.set_row_metadata();
CREATE TRIGGER finding_state_changes_metadata
    BEFORE UPDATE ON finding_state_changes
    FOR EACH ROW EXECUTE FUNCTION sentinel.set_row_metadata();
COMMIT;
