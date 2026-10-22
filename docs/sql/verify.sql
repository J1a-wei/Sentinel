-- 在执行 001、002、003 草案或正式 SQLx 迁移的临时测试库中运行；不验证应用状态机。
-- 正式迁移可额外包含 process_snapshot_entries，统一字段检查同样覆盖该表。
-- 固定 ID、测试行及临时函数全部回滚，可在同一连接重复运行。
BEGIN;
SET LOCAL search_path = sentinel, pg_catalog;
SET LOCAL TIME ZONE 'UTC';
CREATE TEMP TABLE sentinel_verification_results (
    id uuid PRIMARY KEY,
    create_time timestamptz NOT NULL DEFAULT now(),
    update_time timestamptz NOT NULL DEFAULT now(),
    "delete" boolean NOT NULL DEFAULT false,
    name text NOT NULL UNIQUE,
    expected_sqlstate text NOT NULL,
    actual_sqlstate text NOT NULL,
    rejected_table text,
    rejected_constraint text
);
CREATE FUNCTION pg_temp.fixture_id(n integer) RETURNS uuid
LANGUAGE sql IMMUTABLE AS $$ SELECT md5('sentinel-schema-verification:' || n::text)::uuid $$;
CREATE FUNCTION pg_temp.expect_error(test_name text, statement text, expected_state text)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE actual_state text; actual_table text; actual_constraint text;
BEGIN
    BEGIN
        EXECUTE statement;
    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS actual_state = RETURNED_SQLSTATE,
            actual_table = TABLE_NAME, actual_constraint = CONSTRAINT_NAME;
        IF actual_state <> expected_state THEN
            RAISE EXCEPTION 'FAIL [%]: expected SQLSTATE %, received %: %',
                test_name, expected_state, actual_state, SQLERRM;
        END IF;
        INSERT INTO pg_temp.sentinel_verification_results
            (id, name, expected_sqlstate, actual_sqlstate, rejected_table, rejected_constraint)
            VALUES (md5('verification-result:' || test_name)::uuid, test_name, expected_state, actual_state, actual_table, actual_constraint);
        RETURN;
    END;
    -- 位于捕获块之外，避免把断言本身抛出的异常误判为被测语句的预期错误。
    RAISE EXCEPTION 'FAIL [%]: statement succeeded, expected SQLSTATE %', test_name, expected_state;
END;
$$;
CREATE FUNCTION pg_temp.assert_true(test_name text, condition boolean)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    IF condition IS DISTINCT FROM true THEN RAISE EXCEPTION 'FAIL [%]', test_name; END IF;
    INSERT INTO pg_temp.sentinel_verification_results
        (id, name, expected_sqlstate, actual_sqlstate, rejected_table, rejected_constraint)
        VALUES (md5('verification-result:' || test_name)::uuid, test_name, '00000', '00000', NULL, NULL);
END;
$$;

-- 目录级断言覆盖全部业务表，避免只给有 fixture 的表补齐字段。
SELECT pg_temp.assert_true('catalog_all_business_tables_are_regular',
    (SELECT count(*) = 46 + CASE WHEN to_regclass('sentinel.process_snapshot_entries') IS NULL THEN 0 ELSE 1 END
        AND bool_and(c.relkind = 'r')
     FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'sentinel' AND c.relkind IN ('r', 'p')));
SELECT pg_temp.assert_true('catalog_all_tables_have_uniform_metadata', NOT EXISTS (
    SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    CROSS JOIN (VALUES ('id', 'uuid'::regtype), ('create_time', 'timestamptz'::regtype),
        ('update_time', 'timestamptz'::regtype), ('delete', 'boolean'::regtype)) required(name, type_id)
    LEFT JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = required.name AND NOT a.attisdropped
    WHERE n.nspname = 'sentinel' AND c.relkind = 'r'
      AND (a.attnum IS NULL OR a.atttypid <> required.type_id OR NOT a.attnotnull)));
SELECT pg_temp.assert_true('catalog_all_primary_keys_are_id_only', NOT EXISTS (
    SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    LEFT JOIN pg_constraint p ON p.conrelid = c.oid AND p.contype = 'p'
    LEFT JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'id'
    WHERE n.nspname = 'sentinel' AND c.relkind = 'r'
      AND (p.oid IS NULL OR p.conkey <> ARRAY[a.attnum]::smallint[])));
SELECT pg_temp.assert_true('catalog_metadata_defaults_and_application_ids', NOT EXISTS (
    SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname IN ('id', 'create_time', 'update_time', 'delete')
    LEFT JOIN pg_attrdef d ON d.adrelid = c.oid AND d.adnum = a.attnum
    WHERE n.nspname = 'sentinel' AND c.relkind = 'r' AND
      CASE a.attname WHEN 'id' THEN d.oid IS NOT NULL
          WHEN 'delete' THEN pg_get_expr(d.adbin, d.adrelid) IS DISTINCT FROM 'false'
          ELSE pg_get_expr(d.adbin, d.adrelid) IS DISTINCT FROM 'now()' END));
SELECT pg_temp.assert_true('catalog_no_legacy_metadata_names', NOT EXISTS (
    SELECT 1 FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'sentinel' AND c.relkind = 'r' AND NOT a.attisdropped
      AND a.attname IN ('created_at', 'updated_at')));
SELECT pg_temp.assert_true('catalog_all_tables_have_metadata_trigger', NOT EXISTS (
    SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'sentinel' AND c.relkind = 'r' AND NOT EXISTS (
        SELECT 1 FROM pg_trigger t WHERE t.tgrelid = c.oid AND NOT t.tgisinternal
          AND t.tgfoid = 'sentinel.set_row_metadata()'::regprocedure
          AND (t.tgtype::integer & 19) = 19 AND t.tgenabled = 'O')));

-- 正例：两台主机各自具备安装身份；第一台另有合法候选实例和隔离安装身份。
INSERT INTO asset_groups(id, name) VALUES (pg_temp.fixture_id(10), 'verification_group');
INSERT INTO assets(id, group_id, display_name) VALUES
    (pg_temp.fixture_id(20), pg_temp.fixture_id(10), 'verification_asset_a'),
    (pg_temp.fixture_id(21), pg_temp.fixture_id(10), 'verification_asset_b');
INSERT INTO scout_installations(id, asset_id, generation, status) VALUES
    (pg_temp.fixture_id(30), pg_temp.fixture_id(20), 1, 'active'),
    (pg_temp.fixture_id(31), pg_temp.fixture_id(21), 1, 'active'),
    (pg_temp.fixture_id(32), pg_temp.fixture_id(20), 2, 'quarantined');
INSERT INTO scout_instances(id, asset_id, installation_id, role, version, active_epoch, started_at) VALUES
    (pg_temp.fixture_id(40), pg_temp.fixture_id(20), pg_temp.fixture_id(30), 'active', 'fixture-v1', 1, '2000-01-01Z'),
    (pg_temp.fixture_id(41), pg_temp.fixture_id(21), pg_temp.fixture_id(31), 'active', 'fixture-v1', 1, '2000-01-01Z'),
    (pg_temp.fixture_id(42), pg_temp.fixture_id(20), pg_temp.fixture_id(30), 'candidate', 'fixture-v2', NULL, '2000-01-01Z'),
    (pg_temp.fixture_id(43), pg_temp.fixture_id(20), pg_temp.fixture_id(30), 'observer', 'fixture-v2', 2, '2000-01-01Z');
INSERT INTO scout_credentials(id, installation_id, credential_sha256, public_key_sha256, issuer_reference, valid_from, valid_until) VALUES
    (pg_temp.fixture_id(52), pg_temp.fixture_id(30), decode(repeat('c',64),'hex'), decode(repeat('e',64),'hex'), 'fixture', '2000-01-01Z', '2000-01-02Z'),
    (pg_temp.fixture_id(53), pg_temp.fixture_id(30), decode(repeat('d',64),'hex'), decode(repeat('e',64),'hex'), 'fixture', '2000-01-01Z', '2000-01-02Z');
INSERT INTO users(id, display_name) VALUES (pg_temp.fixture_id(50), 'verification_user');
INSERT INTO role_bindings(id, user_id, role_code, scope_kind)
    VALUES (pg_temp.fixture_id(51), pg_temp.fixture_id(50), 'admin', 'global');
INSERT INTO policies(id, name) VALUES (pg_temp.fixture_id(60), 'verification_policy');
INSERT INTO policy_revisions(id, policy_id, revision, schema_version, content, content_sha256)
    VALUES (pg_temp.fixture_id(61), pg_temp.fixture_id(60), 1, 1, '{}', decode(repeat('a', 64), 'hex'));
INSERT INTO policy_bindings(id, policy_revision_id, scope_kind)
    VALUES (pg_temp.fixture_id(62), pg_temp.fixture_id(61), 'default');
INSERT INTO scout_releases(id, version_label, image_reference, image_digest, signature_metadata,
    platform_constraints, deployment_spec, deployment_schema_version, compatibility) VALUES
    (pg_temp.fixture_id(70), 'fixture-v1', 'example.invalid/scout', 'sha256:' || repeat('a', 64), '{}', '{}', '{}', 1, '{}'),
    (pg_temp.fixture_id(71), 'fixture-v2', 'example.invalid/scout', 'sha256:' || repeat('b', 64), '{}', '{}', '{}', 1, '{}');
INSERT INTO asset_desired_states(id, asset_id, generation, policy_revision_id, release_id, resolved_config, config_sha256, reason) VALUES
    (pg_temp.fixture_id(201), pg_temp.fixture_id(20), 1, pg_temp.fixture_id(61), pg_temp.fixture_id(70), '{}', decode(repeat('a', 64), 'hex'), 'fixture'),
    (pg_temp.fixture_id(202), pg_temp.fixture_id(20), 2, pg_temp.fixture_id(61), pg_temp.fixture_id(71), '{}', decode(repeat('a', 64), 'hex'), 'fixture'),
    (pg_temp.fixture_id(203), pg_temp.fixture_id(21), 1, pg_temp.fixture_id(61), pg_temp.fixture_id(70), '{}', decode(repeat('a', 64), 'hex'), 'fixture');
INSERT INTO asset_control_states(id, asset_id, desired_generation, active_installation_id, active_instance_id, active_epoch)
    VALUES (pg_temp.fixture_id(204), pg_temp.fixture_id(20), 2, pg_temp.fixture_id(30), pg_temp.fixture_id(40), 1);
INSERT INTO tasks(id, asset_id, kind, origin, desired_generation, parameters_schema_version, parameters, not_before, deadline_at) VALUES
    (pg_temp.fixture_id(80), pg_temp.fixture_id(20), 'diagnostic', 'manual', 1, 1, '{}', '2000-01-01Z', '2000-01-02Z'),
    (pg_temp.fixture_id(81), pg_temp.fixture_id(21), 'diagnostic', 'manual', 1, 1, '{}', '2000-01-01Z', '2000-01-02Z'),
    (pg_temp.fixture_id(82), pg_temp.fixture_id(20), 'upgrade', 'rollout', 2, 1, '{}', '2000-01-01Z', '2000-01-02Z');
INSERT INTO task_attempts(id, task_id, asset_id, attempt_no) VALUES
    (pg_temp.fixture_id(90), pg_temp.fixture_id(80), pg_temp.fixture_id(20), 1),
    (pg_temp.fixture_id(91), pg_temp.fixture_id(81), pg_temp.fixture_id(21), 1),
    (pg_temp.fixture_id(92), pg_temp.fixture_id(82), pg_temp.fixture_id(20), 1);
UPDATE tasks SET current_attempt_id = pg_temp.fixture_id(90) WHERE id = pg_temp.fixture_id(80);
INSERT INTO upgrade_attempt_details(id, attempt_id, task_id, asset_id, desired_generation, installation_id,
    previous_release_id, target_release_id, old_instance_id, candidate_instance_id, phase, phase_sequence)
    VALUES (pg_temp.fixture_id(205), pg_temp.fixture_id(92), pg_temp.fixture_id(82), pg_temp.fixture_id(20), 2, pg_temp.fixture_id(30),
        pg_temp.fixture_id(70), pg_temp.fixture_id(71), pg_temp.fixture_id(40), pg_temp.fixture_id(42), 'preflight', 0);
INSERT INTO outbox_messages(id, message_type, asset_id, task_id, attempt_id, subject, schema_version, payload)
    VALUES (pg_temp.fixture_id(95), 'task.dispatch', pg_temp.fixture_id(20), pg_temp.fixture_id(80),
        pg_temp.fixture_id(90), 'verification.task', 1, '{}');
INSERT INTO inbox_receipts(id, handler_key, producer_installation_id, event_id, asset_id, payload_sha256)
    VALUES (pg_temp.fixture_id(206), 'verification', pg_temp.fixture_id(30), pg_temp.fixture_id(96), pg_temp.fixture_id(20), decode(repeat('a',64),'hex'));

-- 正例：快照、采集运行、任务和策略关联；同安装身份的 sequence 不重复。
INSERT INTO package_snapshots(id, asset_id, content_sha256, schema_version, os_id, os_version, architecture, package_count) VALUES
    (pg_temp.fixture_id(100), pg_temp.fixture_id(20), decode(repeat('a',64),'hex'), 1, 'ubuntu', '24.04', 'amd64', 1),
    (pg_temp.fixture_id(101), pg_temp.fixture_id(21), decode(repeat('b',64),'hex'), 1, 'ubuntu', '24.04', 'amd64', 1);
INSERT INTO package_entries(id, snapshot_id, package_name, architecture, version, source_name, source_version, origin_status) VALUES
    (pg_temp.fixture_id(207), pg_temp.fixture_id(100), 'fixture-package', 'amd64', '1.0-1ubuntu1', 'fixture-source', '1.0-1ubuntu1', 'ubuntu'),
    (pg_temp.fixture_id(208), pg_temp.fixture_id(101), 'fixture-package', 'amd64', '1.0-1ubuntu1', 'fixture-source', '1.0-1ubuntu1', 'ubuntu');
INSERT INTO collection_runs(id, asset_id, installation_id, instance_id, active_epoch, sequence, kind, status,
    schema_version, collector_revision, policy_revision_id, package_snapshot_id, expected_scope, started_at, finished_at) VALUES
    (pg_temp.fixture_id(110), pg_temp.fixture_id(20), pg_temp.fixture_id(30), pg_temp.fixture_id(40), 1, 1, 'packages', 'complete', 1, 'fixture', pg_temp.fixture_id(61), pg_temp.fixture_id(100), '{}', '2000-01-01Z', '2000-01-01 00:01Z'),
    (pg_temp.fixture_id(111), pg_temp.fixture_id(20), pg_temp.fixture_id(30), pg_temp.fixture_id(40), 1, 2, 'baseline', 'complete', 1, 'fixture', pg_temp.fixture_id(61), NULL, '{}', '2000-01-01Z', '2000-01-01 00:01Z'),
    (pg_temp.fixture_id(112), pg_temp.fixture_id(20), pg_temp.fixture_id(30), pg_temp.fixture_id(40), 1, 3, 'ports', 'complete', 1, 'fixture', pg_temp.fixture_id(61), NULL, '{}', '2000-01-01Z', '2000-01-01 00:01Z'),
    (pg_temp.fixture_id(113), pg_temp.fixture_id(20), pg_temp.fixture_id(30), pg_temp.fixture_id(40), 1, 4, 'inventory', 'complete', 1, 'fixture', pg_temp.fixture_id(61), NULL, '{}', '2000-01-01Z', '2000-01-01 00:01Z'),
    (pg_temp.fixture_id(114), pg_temp.fixture_id(21), pg_temp.fixture_id(31), pg_temp.fixture_id(41), 1, 1, 'baseline', 'complete', 1, 'fixture', pg_temp.fixture_id(61), NULL, '{}', '2000-01-01Z', '2000-01-01 00:01Z');
UPDATE collection_runs SET task_attempt_id = pg_temp.fixture_id(90) WHERE id = pg_temp.fixture_id(113);
INSERT INTO asset_inventory_snapshots(id, collection_run_id, asset_id, hostname)
    VALUES (pg_temp.fixture_id(209), pg_temp.fixture_id(113), pg_temp.fixture_id(20), 'verification-host');
INSERT INTO port_snapshot_endpoints(id, collection_run_id, asset_id, network_namespace, protocol, local_address, local_port)
    VALUES (pg_temp.fixture_id(210), pg_temp.fixture_id(112), pg_temp.fixture_id(20), 'host', 'tcp', '127.0.0.1', 22);

-- 正例：固定情报 -> 同资产清单评估 -> 逐包覆盖 -> 结果 -> 风险投影。
INSERT INTO vulnerability_intelligence_revisions(id, source_key, upstream_revision, content_sha256, status,
    retrieved_at, last_checked_at, ready_at) VALUES
    (pg_temp.fixture_id(120), 'verification', 'r1', repeat('a',64), 'ready', '2000-01-01Z', '2000-01-01Z', '2000-01-01Z'),
    (pg_temp.fixture_id(121), 'verification', 'r2', repeat('b',64), 'ready', '2000-01-01Z', '2000-01-01Z', '2000-01-01Z');
INSERT INTO ubuntu_package_advisories(id, intelligence_revision_id, cve_id, ubuntu_release, source_name,
    architecture_scope, upstream_status, verdict, fixed_version, severity, reference_url, source_record) VALUES
    (pg_temp.fixture_id(130), pg_temp.fixture_id(120), 'CVE-2000-12345', '24.04', 'fixture-source', 'all', 'released', 'affected_fix_available', '2.0-1ubuntu1', 'high', 'https://example.invalid/fixture', '{}'),
    (pg_temp.fixture_id(131), pg_temp.fixture_id(121), 'CVE-2000-12345', '24.04', 'fixture-source', 'all', 'released', 'affected_fix_available', '2.0-1ubuntu2', 'high', 'https://example.invalid/fixture', '{}');
INSERT INTO vulnerability_evaluation_runs(id, asset_id, snapshot_id, intelligence_revision_id, matcher_revision,
    status, requested_at, started_at, finished_at) VALUES
    (pg_temp.fixture_id(140), pg_temp.fixture_id(20), pg_temp.fixture_id(100), pg_temp.fixture_id(120), 'fixture', 'complete', '2000-01-01Z', '2000-01-01Z', '2000-01-01 00:01Z'),
    (pg_temp.fixture_id(141), pg_temp.fixture_id(21), pg_temp.fixture_id(101), pg_temp.fixture_id(120), 'fixture', 'complete', '2000-01-01Z', '2000-01-01Z', '2000-01-01 00:01Z'),
    (pg_temp.fixture_id(142), pg_temp.fixture_id(20), pg_temp.fixture_id(100), pg_temp.fixture_id(120), 'fixture', 'complete', '2000-01-01Z', '2000-01-01Z', '2000-01-01 00:01Z');
INSERT INTO vulnerability_package_coverage(id, evaluation_id, snapshot_id, package_name, architecture, status) VALUES
    (pg_temp.fixture_id(211), pg_temp.fixture_id(140), pg_temp.fixture_id(100), 'fixture-package', 'amd64', 'assessed'),
    (pg_temp.fixture_id(212), pg_temp.fixture_id(141), pg_temp.fixture_id(101), 'fixture-package', 'amd64', 'assessed'),
    (pg_temp.fixture_id(213), pg_temp.fixture_id(142), pg_temp.fixture_id(100), 'fixture-package', 'amd64', 'assessed');
INSERT INTO vulnerability_results(id, evaluation_id, asset_id, intelligence_revision_id, package_name, architecture,
    cve_id, advisory_id, verdict, fixed_version, severity, reason_code, evaluated_at) VALUES
    (pg_temp.fixture_id(150), pg_temp.fixture_id(140), pg_temp.fixture_id(20), pg_temp.fixture_id(120), 'fixture-package', 'amd64', 'CVE-2000-12345', pg_temp.fixture_id(130), 'affected_fix_available', '2.0-1ubuntu1', 'high', 'fixture', '2000-01-01 00:01Z'),
    (pg_temp.fixture_id(151), pg_temp.fixture_id(141), pg_temp.fixture_id(21), pg_temp.fixture_id(120), 'fixture-package', 'amd64', 'CVE-2000-12345', pg_temp.fixture_id(130), 'affected_fix_available', '2.0-1ubuntu1', 'high', 'fixture', '2000-01-01 00:01Z');
INSERT INTO asset_vulnerability_heads(id, asset_id, latest_attempt_id, latest_complete_id)
    VALUES (pg_temp.fixture_id(214), pg_temp.fixture_id(20), pg_temp.fixture_id(140), pg_temp.fixture_id(140));
INSERT INTO baseline_rule_revisions(id, rule_key, revision, title, severity, applicable_scope, specification,
    remediation, content_sha256, create_time)
    VALUES (pg_temp.fixture_id(160), 'verification.ssh', 1, 'fixture', 'high', '{}', '{}', 'fixture', repeat('a',64), '2000-01-01Z');
INSERT INTO baseline_results(id, collection_run_id, asset_id, rule_revision_id, rule_key, context_key,
    verdict, configuration_view, runtime_confirmation, evaluated_at)
    VALUES (pg_temp.fixture_id(170), pg_temp.fixture_id(111), pg_temp.fixture_id(20), pg_temp.fixture_id(160),
        'verification.ssh', 'fixture-context', 'fail', 'disk', 'unconfirmed', '2000-01-01 00:01Z');
INSERT INTO findings(id, asset_id, kind, finding_key, technical_state, severity, first_seen_at, last_seen_at,
    last_evaluated_at, vulnerability_result_id, baseline_result_id) VALUES
    (pg_temp.fixture_id(180), pg_temp.fixture_id(20), 'vulnerability', 'fixture-vulnerability', 'present', 'high', '2000-01-01Z', '2000-01-01Z', '2000-01-01Z', pg_temp.fixture_id(150), NULL),
    (pg_temp.fixture_id(181), pg_temp.fixture_id(20), 'baseline', 'fixture-baseline', 'present', 'high', '2000-01-01Z', '2000-01-01Z', '2000-01-01Z', NULL, pg_temp.fixture_id(170));
INSERT INTO finding_state_changes(id, finding_id, asset_id, kind, finding_version, change_type, technical_state,
    disposition, vulnerability_result_id, actor_kind, actor_reference, reason_code, changed_at)
    VALUES (pg_temp.fixture_id(190), pg_temp.fixture_id(180), pg_temp.fixture_id(20), 'vulnerability', 1,
        'created', 'present', 'open', pg_temp.fixture_id(150), 'system', 'fixture', 'fixture', '2000-01-01Z');

-- 正例：三类指标在普通表内分别保存分钟/小时行，统一使用独立 UUID 主键。
-- 每个桶分成两个不重叠半段；第二段 revision 可从 1 开始，不能覆盖第一段。
INSERT INTO host_metric_buckets(id, asset_id, installation_id, instance_id, active_epoch,
    resolution_seconds, bucket_start, observed_from, observed_until, revision, sample_count,
    cpu_percent_seconds_sum, cpu_observed_seconds, cpu_percent_max, memory_used_byte_seconds,
    memory_observed_seconds, memory_used_bytes_max, memory_total_bytes_last)
    SELECT pg_temp.fixture_id(2000+r*10+e), pg_temp.fixture_id(20), pg_temp.fixture_id(30), pg_temp.fixture_id(CASE e WHEN 1 THEN 40 ELSE 43 END), e,
        r, '2000-01-01Z'::timestamptz, '2000-01-01Z'::timestamptz + (e-1)*r/2 * interval '1 second',
        '2000-01-01Z'::timestamptz + e*r/2 * interval '1 second', 1, 1, 10*r/2, r/2, 10, 100*r/2, r/2, 100, 1000
    FROM unnest(ARRAY[60,3600]) AS r CROSS JOIN unnest(ARRAY[1,2]) AS e;
INSERT INTO network_metric_buckets(id, asset_id, installation_id, instance_id, active_epoch,
    resolution_seconds, bucket_start, observed_from, observed_until, resource_key, interface_name,
    interface_kind, revision, sample_count, observed_seconds, rx_bytes_delta, tx_bytes_delta,
    rx_bytes_per_second_max, tx_bytes_per_second_max)
    SELECT pg_temp.fixture_id(40000+r*10+e), pg_temp.fixture_id(20), pg_temp.fixture_id(30), pg_temp.fixture_id(CASE e WHEN 1 THEN 40 ELSE 43 END), e,
        r, '2000-01-01Z'::timestamptz, '2000-01-01Z'::timestamptz + (e-1)*r/2 * interval '1 second',
        '2000-01-01Z'::timestamptz + e*r/2 * interval '1 second', 'fixture-boot:eth0', 'eth0', 'physical', 1, 1, r/2, 10*r/2, 20*r/2, 10, 20
    FROM unnest(ARRAY[60,3600]) AS r CROSS JOIN unnest(ARRAY[1,2]) AS e;
INSERT INTO filesystem_metric_buckets(id, asset_id, installation_id, instance_id, active_epoch,
    resolution_seconds, bucket_start, observed_from, observed_until, resource_key, mount_point,
    revision, sample_count, observed_seconds, total_bytes_last, available_bytes_last, used_bytes_max, inode_available_min)
    SELECT pg_temp.fixture_id(80000+r*10+e), pg_temp.fixture_id(20), pg_temp.fixture_id(30), pg_temp.fixture_id(CASE e WHEN 1 THEN 40 ELSE 43 END), e,
        r, '2000-01-01Z'::timestamptz, '2000-01-01Z'::timestamptz + (e-1)*r/2 * interval '1 second',
        '2000-01-01Z'::timestamptz + e*r/2 * interval '1 second', 'fixture-boot:root', '/', 1, 1, r/2, 1000, 900, 100, 50
    FROM unnest(ARRAY[60,3600]) AS r CROSS JOIN unnest(ARRAY[1,2]) AS e;
SELECT pg_temp.assert_true('positive_identity_candidate', (SELECT count(*) = 2 FROM scout_instances WHERE asset_id = pg_temp.fixture_id(20) AND role IN ('active', 'candidate')));
SELECT pg_temp.assert_true('positive_same_public_key_renewed_credentials', (SELECT count(*) = 2 AND count(DISTINCT public_key_sha256) = 1 FROM scout_credentials WHERE installation_id = pg_temp.fixture_id(30)));
SELECT pg_temp.assert_true('positive_control_and_collection_links', (SELECT task_attempt_id = pg_temp.fixture_id(90) FROM collection_runs WHERE id = pg_temp.fixture_id(113)));
SELECT pg_temp.assert_true('positive_vulnerability_chain', (SELECT count(*) = 2 FROM vulnerability_results WHERE id IN (pg_temp.fixture_id(150), pg_temp.fixture_id(151))));
SELECT pg_temp.assert_true('positive_baseline_and_findings', (SELECT count(*) = 2 FROM findings WHERE asset_id = pg_temp.fixture_id(20)));
SELECT pg_temp.assert_true('positive_metric_resolutions_in_regular_tables',
    (SELECT count(DISTINCT tableoid) = 1 AND count(DISTINCT resolution_seconds) = 2 FROM host_metric_buckets)
    AND (SELECT count(DISTINCT tableoid) = 1 AND count(DISTINCT resolution_seconds) = 2 FROM network_metric_buckets)
    AND (SELECT count(DISTINCT tableoid) = 1 AND count(DISTINCT resolution_seconds) = 2 FROM filesystem_metric_buckets));
SELECT pg_temp.assert_true('positive_same_bucket_separate_epochs',
    (SELECT count(*) = 2 AND count(DISTINCT active_epoch) = 2 FROM host_metric_buckets WHERE resolution_seconds = 60)
    AND (SELECT count(*) = 2 AND count(DISTINCT active_epoch) = 2 FROM network_metric_buckets WHERE resolution_seconds = 60)
    AND (SELECT count(*) = 2 AND count(DISTINCT active_epoch) = 2 FROM filesystem_metric_buckets WHERE resolution_seconds = 60));

-- 反例均在函数内部子事务回滚，后续测试继续使用未被污染的有效 fixture。
SELECT pg_temp.expect_error('asset_requires_group', $q$
    INSERT INTO assets(id, display_name) VALUES (pg_temp.fixture_id(900), 'fixture') $q$, '23502');
SELECT pg_temp.expect_error('credential_fingerprint_replay', $q$
    INSERT INTO scout_credentials(id, installation_id, credential_sha256, public_key_sha256, issuer_reference, valid_from, valid_until)
    VALUES (pg_temp.fixture_id(900), pg_temp.fixture_id(30), decode(repeat('c',64),'hex'), decode(repeat('e',64),'hex'), 'fixture', '2000-01-01Z', '2000-01-02Z') $q$, '23505');
SELECT pg_temp.expect_error('one_active_installation', $q$
    UPDATE scout_installations SET status = 'active' WHERE id = pg_temp.fixture_id(32) $q$, '23505');
SELECT pg_temp.expect_error('one_active_instance', $q$
    UPDATE scout_instances SET role = 'active', active_epoch = 2 WHERE id = pg_temp.fixture_id(42) $q$, '23505');
SELECT pg_temp.expect_error('instance_installation_asset_mismatch', $q$
    INSERT INTO scout_instances(id, asset_id, installation_id, role, version, started_at)
    VALUES (pg_temp.fixture_id(900), pg_temp.fixture_id(20), pg_temp.fixture_id(31), 'candidate', 'fixture', '2000-01-01Z') $q$, '23503');
SELECT pg_temp.expect_error('collection_source_asset_mismatch', $q$
    UPDATE collection_runs SET instance_id = pg_temp.fixture_id(41) WHERE id = pg_temp.fixture_id(112) $q$, '23503');
SELECT pg_temp.expect_error('collection_sequence_replay', $q$
    UPDATE collection_runs SET sequence = 1 WHERE id = pg_temp.fixture_id(112) $q$, '23505');
SELECT pg_temp.expect_error('inventory_rejects_ports_run', $q$
    UPDATE asset_inventory_snapshots SET collection_run_id = pg_temp.fixture_id(112) WHERE collection_run_id = pg_temp.fixture_id(113) $q$, '23503');
SELECT pg_temp.expect_error('package_snapshot_asset_mismatch', $q$
    UPDATE collection_runs SET package_snapshot_id = pg_temp.fixture_id(101) WHERE id = pg_temp.fixture_id(110) $q$, '23503');
SELECT pg_temp.expect_error('port_requires_host_address_not_subnet', $q$
    UPDATE port_snapshot_endpoints SET local_address = '127.0.0.0/8' WHERE collection_run_id = pg_temp.fixture_id(112) $q$, '23514');
SELECT pg_temp.expect_error('global_role_binding_replay', $q$
    INSERT INTO role_bindings(id, user_id, role_code, scope_kind) VALUES
        (pg_temp.fixture_id(900), pg_temp.fixture_id(50), 'admin', 'global') $q$, '23505');
SELECT pg_temp.expect_error('global_role_rejects_group_id', $q$
    UPDATE role_bindings SET group_id = pg_temp.fixture_id(10) WHERE id = pg_temp.fixture_id(51) $q$, '23514');
SELECT pg_temp.expect_error('one_default_policy_binding', $q$
    INSERT INTO policy_bindings(id, policy_revision_id, scope_kind) VALUES
        (pg_temp.fixture_id(900), pg_temp.fixture_id(61), 'default') $q$, '23505');
SELECT pg_temp.expect_error('desired_generation_replay', $q$
    INSERT INTO asset_desired_states
    SELECT (jsonb_populate_record(NULL::asset_desired_states, to_jsonb(t) || jsonb_build_object('id', pg_temp.fixture_id(900)))).*
    FROM asset_desired_states AS t WHERE asset_id = pg_temp.fixture_id(20) AND generation = 1 LIMIT 1 $q$, '23505');
SELECT pg_temp.expect_error('one_pending_upgrade_per_asset', $q$
    INSERT INTO tasks(id, asset_id, kind, origin, desired_generation, parameters_schema_version, parameters, not_before, deadline_at)
    VALUES (pg_temp.fixture_id(900), pg_temp.fixture_id(20), 'upgrade', 'manual', 2, 1, '{}', '2000-01-01Z', '2000-01-02Z') $q$, '23505');
SELECT pg_temp.expect_error('upgrade_requires_desired_generation', $q$
    UPDATE tasks SET desired_generation = NULL WHERE id = pg_temp.fixture_id(82) $q$, '23514');
SELECT pg_temp.expect_error('one_open_attempt_per_task', $q$
    INSERT INTO task_attempts(id, task_id, asset_id, attempt_no) VALUES
        (pg_temp.fixture_id(900), pg_temp.fixture_id(80), pg_temp.fixture_id(20), 2) $q$, '23505');
-- 用终结尝试单独检查跨资产 FK，避免同时违反未终结尝试唯一键。
SELECT pg_temp.expect_error('attempt_task_asset_foreign_key', $q$
    INSERT INTO task_attempts(id, task_id, asset_id, attempt_no, state) VALUES
        (pg_temp.fixture_id(900), pg_temp.fixture_id(80), pg_temp.fixture_id(21), 2, 'failed') $q$, '23503');
SELECT pg_temp.expect_error('current_attempt_wrong_task_same_asset', $q$
    UPDATE tasks SET current_attempt_id = pg_temp.fixture_id(92) WHERE id = pg_temp.fixture_id(80) $q$, '23503');
SELECT pg_temp.expect_error('collection_attempt_wrong_asset', $q$
    UPDATE collection_runs SET task_attempt_id = pg_temp.fixture_id(91) WHERE id = pg_temp.fixture_id(113) $q$, '23503');
SELECT pg_temp.expect_error('upgrade_release_differs_from_desired', $q$
    UPDATE upgrade_attempt_details SET target_release_id = pg_temp.fixture_id(70) WHERE attempt_id = pg_temp.fixture_id(92) $q$, '23503');
SELECT pg_temp.expect_error('outbox_attempt_wrong_task', $q$
    UPDATE outbox_messages SET attempt_id = pg_temp.fixture_id(92) WHERE id = pg_temp.fixture_id(95) $q$, '23503');
SELECT pg_temp.expect_error('inbox_event_replay', $q$
    INSERT INTO inbox_receipts
    SELECT (jsonb_populate_record(NULL::inbox_receipts, to_jsonb(t) || jsonb_build_object('id', pg_temp.fixture_id(900)))).*
    FROM inbox_receipts AS t WHERE event_id = pg_temp.fixture_id(96) LIMIT 1 $q$, '23505');
SELECT pg_temp.expect_error('evaluation_snapshot_wrong_asset', $q$
    INSERT INTO vulnerability_evaluation_runs(id, asset_id, snapshot_id, intelligence_revision_id, matcher_revision, status, requested_at)
    VALUES (pg_temp.fixture_id(900), pg_temp.fixture_id(21), pg_temp.fixture_id(100), pg_temp.fixture_id(120), 'fixture', 'queued', '2000-01-01Z') $q$, '23503');
SELECT pg_temp.expect_error('coverage_snapshot_differs_from_evaluation', $q$
    UPDATE vulnerability_package_coverage SET snapshot_id = pg_temp.fixture_id(101) WHERE evaluation_id = pg_temp.fixture_id(140) $q$, '23503');
SELECT pg_temp.expect_error('coverage_unknown_requires_reason', $q$
    UPDATE vulnerability_package_coverage SET status = 'unknown', reason_code = NULL WHERE evaluation_id = pg_temp.fixture_id(140) $q$, '23514');
SELECT pg_temp.expect_error('vulnerability_result_wrong_asset', $q$
    INSERT INTO vulnerability_results(id, evaluation_id, asset_id, intelligence_revision_id, package_name, architecture,
        cve_id, advisory_id, verdict, fixed_version, severity, reason_code, evaluated_at)
    SELECT pg_temp.fixture_id(900), pg_temp.fixture_id(142), pg_temp.fixture_id(21), intelligence_revision_id, package_name,
        architecture, cve_id, advisory_id, verdict, fixed_version, severity, reason_code, evaluated_at
    FROM vulnerability_results WHERE id = pg_temp.fixture_id(150) $q$, '23503');
SELECT pg_temp.expect_error('vulnerability_result_wrong_feed', $q$
    INSERT INTO vulnerability_results(id, evaluation_id, asset_id, intelligence_revision_id, package_name, architecture,
        cve_id, advisory_id, verdict, fixed_version, severity, reason_code, evaluated_at)
    SELECT pg_temp.fixture_id(900), pg_temp.fixture_id(142), asset_id, pg_temp.fixture_id(121), package_name,
        architecture, cve_id, pg_temp.fixture_id(131), verdict, fixed_version, severity, reason_code, evaluated_at
    FROM vulnerability_results WHERE id = pg_temp.fixture_id(150) $q$, '23503');
SELECT pg_temp.expect_error('vulnerability_advisory_wrong_feed', $q$
    UPDATE vulnerability_results SET advisory_id = pg_temp.fixture_id(131) WHERE id = pg_temp.fixture_id(150) $q$, '23503');
SELECT pg_temp.expect_error('vulnerability_result_without_package_coverage', $q$
    UPDATE vulnerability_results SET package_name = 'uncovered-package' WHERE id = pg_temp.fixture_id(150) $q$, '23503');
SELECT pg_temp.expect_error('vulnerability_fix_requires_version', $q$
    UPDATE vulnerability_results SET fixed_version = NULL WHERE id = pg_temp.fixture_id(150) $q$, '23514');
SELECT pg_temp.expect_error('vulnerability_head_wrong_asset', $q$
    UPDATE asset_vulnerability_heads SET latest_complete_id = pg_temp.fixture_id(141) WHERE asset_id = pg_temp.fixture_id(20) $q$, '23503');
SELECT pg_temp.expect_error('baseline_rejects_ports_run', $q$
    UPDATE baseline_results SET collection_run_id = pg_temp.fixture_id(112) WHERE id = pg_temp.fixture_id(170) $q$, '23503');
SELECT pg_temp.expect_error('baseline_unknown_requires_reason', $q$
    UPDATE baseline_results SET verdict = 'unknown', reason_code = NULL WHERE id = pg_temp.fixture_id(170) $q$, '23514');
SELECT pg_temp.expect_error('finding_wrong_asset_result', $q$
    UPDATE findings SET vulnerability_result_id = pg_temp.fixture_id(151) WHERE id = pg_temp.fixture_id(180) $q$, '23503');
SELECT pg_temp.expect_error('finding_resolved_requires_timestamp', $q$
    UPDATE findings SET technical_state = 'resolved', resolved_at = NULL WHERE id = pg_temp.fixture_id(180) $q$, '23514');
SELECT pg_temp.expect_error('finding_present_rejects_resolution_timestamp', $q$
    UPDATE findings SET resolved_at = '2000-01-01Z' WHERE id = pg_temp.fixture_id(180) $q$, '23514');
SELECT pg_temp.expect_error('finding_accepted_risk_requires_reason', $q$
    UPDATE findings SET disposition = 'accepted_risk', disposition_reason = NULL WHERE id = pg_temp.fixture_id(180) $q$, '23514');
SELECT pg_temp.expect_error('finding_closure_evaluation_wrong_asset', $q$
    UPDATE findings SET technical_state = 'resolved', resolved_at = '2000-01-01Z', closure_evaluation_id = pg_temp.fixture_id(141)
        WHERE id = pg_temp.fixture_id(180) $q$, '23503');
SELECT pg_temp.expect_error('finding_history_requires_previous_states', $q$
    UPDATE finding_state_changes SET change_type = 'assessment' WHERE id = pg_temp.fixture_id(190) $q$, '23514');
SELECT pg_temp.expect_error('host_minute_bucket_replay', $q$
    INSERT INTO host_metric_buckets
    SELECT (jsonb_populate_record(NULL::host_metric_buckets, to_jsonb(t) || jsonb_build_object('id', pg_temp.fixture_id(900)))).*
    FROM host_metric_buckets AS t WHERE resolution_seconds = 60 LIMIT 1 $q$, '23505');
SELECT pg_temp.expect_error('network_minute_bucket_replay', $q$
    INSERT INTO network_metric_buckets
    SELECT (jsonb_populate_record(NULL::network_metric_buckets, to_jsonb(t) || jsonb_build_object('id', pg_temp.fixture_id(900)))).*
    FROM network_metric_buckets AS t WHERE resolution_seconds = 60 LIMIT 1 $q$, '23505');
SELECT pg_temp.expect_error('filesystem_hour_bucket_replay', $q$
    INSERT INTO filesystem_metric_buckets
    SELECT (jsonb_populate_record(NULL::filesystem_metric_buckets, to_jsonb(t) || jsonb_build_object('id', pg_temp.fixture_id(900)))).*
    FROM filesystem_metric_buckets AS t WHERE resolution_seconds = 3600 LIMIT 1 $q$, '23505');
SELECT pg_temp.expect_error('bucket_start_requires_alignment', $q$
    UPDATE host_metric_buckets SET bucket_start = bucket_start + interval '1 second',
        observed_from = observed_from + interval '1 second', observed_until = observed_until + interval '1 second'
    WHERE resolution_seconds = 60 $q$, '23514');
SELECT pg_temp.expect_error('cpu_integral_cannot_exceed_observed_time', $q$
    UPDATE host_metric_buckets SET cpu_percent_seconds_sum = 6001 WHERE resolution_seconds = 60 $q$, '23514');
SELECT pg_temp.expect_error('metric_bucket_requires_asset', $q$
    UPDATE filesystem_metric_buckets SET asset_id = pg_temp.fixture_id(999) WHERE resolution_seconds = 60 $q$, '23503');
SELECT pg_temp.expect_error('metric_instance_requires_same_asset', $q$
    UPDATE network_metric_buckets SET instance_id = pg_temp.fixture_id(41) WHERE resolution_seconds = 60 $q$, '23503');
SELECT pg_temp.expect_error('metric_interval_stays_inside_bucket', $q$
    UPDATE network_metric_buckets SET observed_until = '2000-01-01 00:01:01Z' WHERE resolution_seconds = 60 $q$, '23514');
SELECT pg_temp.expect_error('metric_observed_duration_fits_segment', $q$
    UPDATE host_metric_buckets SET cpu_observed_seconds = 31 WHERE resolution_seconds = 60 AND active_epoch = 1 $q$, '23514');

SELECT pg_temp.assert_true('fixtures_survive_expected_errors',
    (SELECT technical_state = 'present' AND resolved_at IS NULL FROM findings WHERE id = pg_temp.fixture_id(180))
    AND (SELECT count(*) = 4 FROM host_metric_buckets)
    AND (SELECT current_attempt_id = pg_temp.fixture_id(90) FROM tasks WHERE id = pg_temp.fixture_id(80)));
-- 通用元数据：默认值、自动更新时间及不可改写的稳定身份。
INSERT INTO asset_groups(id, name, create_time, update_time)
    VALUES (pg_temp.fixture_id(300), 'verification_metadata', '2000-01-01Z', '2000-01-01Z');
SELECT pg_temp.assert_true('metadata_delete_defaults_false',
    (SELECT NOT "delete" FROM asset_groups WHERE id = pg_temp.fixture_id(300)));
DO $$
DECLARE previous_time timestamptz; original_create_time timestamptz;
BEGIN
    SELECT update_time, create_time INTO previous_time, original_create_time
        FROM asset_groups WHERE id = pg_temp.fixture_id(300);
    UPDATE asset_groups SET description = 'updated', update_time = '1900-01-01Z'
        WHERE id = pg_temp.fixture_id(300);
    PERFORM pg_temp.assert_true('metadata_normal_update_advances_time',
        (SELECT update_time > previous_time AND create_time = original_create_time
         FROM asset_groups WHERE id = pg_temp.fixture_id(300)));
    SELECT update_time INTO previous_time FROM asset_groups WHERE id = pg_temp.fixture_id(300);
    UPDATE asset_groups SET "delete" = true WHERE id = pg_temp.fixture_id(300);
    PERFORM pg_temp.assert_true('metadata_soft_delete_advances_time',
        (SELECT "delete" AND update_time > previous_time AND create_time = original_create_time
         FROM asset_groups WHERE id = pg_temp.fixture_id(300)));
END;
$$;
SELECT pg_temp.expect_error('metadata_id_is_immutable', $q$
    UPDATE asset_groups SET id = pg_temp.fixture_id(900) WHERE id = pg_temp.fixture_id(300) $q$, '23514');
SELECT pg_temp.expect_error('metadata_create_time_is_immutable', $q$
    UPDATE asset_groups SET create_time = create_time + interval '1 second' WHERE id = pg_temp.fixture_id(300) $q$, '23514');
SELECT pg_temp.expect_error('metadata_requires_application_supplied_id', $q$
    INSERT INTO asset_groups(name) VALUES ('verification_missing_id') $q$, '23502');

-- 三类指标 id 在整表唯一；换到其他时间桶也不能复用，不能退化为 (id, bucket) 主键。
SELECT pg_temp.expect_error('host_metric_id_unique_across_buckets', $q$
    INSERT INTO host_metric_buckets
    SELECT (jsonb_populate_record(NULL::host_metric_buckets, to_jsonb(t) || jsonb_build_object(
        'bucket_start', bucket_start + interval '1 day', 'observed_from', observed_from + interval '1 day',
        'observed_until', observed_until + interval '1 day'))).*
    FROM host_metric_buckets t WHERE resolution_seconds = 60 LIMIT 1 $q$, '23505');
SELECT pg_temp.expect_error('network_metric_id_unique_across_buckets', $q$
    INSERT INTO network_metric_buckets
    SELECT (jsonb_populate_record(NULL::network_metric_buckets, to_jsonb(t) || jsonb_build_object(
        'bucket_start', bucket_start + interval '1 day', 'observed_from', observed_from + interval '1 day',
        'observed_until', observed_until + interval '1 day'))).*
    FROM network_metric_buckets t WHERE resolution_seconds = 60 LIMIT 1 $q$, '23505');
SELECT pg_temp.expect_error('filesystem_metric_id_unique_across_buckets', $q$
    INSERT INTO filesystem_metric_buckets
    SELECT (jsonb_populate_record(NULL::filesystem_metric_buckets, to_jsonb(t) || jsonb_build_object(
        'bucket_start', bucket_start + interval '1 day', 'observed_from', observed_from + interval '1 day',
        'observed_until', observed_until + interval '1 day'))).*
    FROM filesystem_metric_buckets t WHERE resolution_seconds = 60 LIMIT 1 $q$, '23505');
SELECT pg_temp.expect_error('inventory_run_remains_unique_with_new_id', $q$
    INSERT INTO asset_inventory_snapshots
    SELECT (jsonb_populate_record(NULL::asset_inventory_snapshots,
        to_jsonb(t) || jsonb_build_object('id', pg_temp.fixture_id(900)))).*
    FROM asset_inventory_snapshots t WHERE collection_run_id = pg_temp.fixture_id(113) $q$, '23505');
SELECT pg_temp.expect_error('port_endpoint_remains_unique_with_new_id', $q$
    INSERT INTO port_snapshot_endpoints
    SELECT (jsonb_populate_record(NULL::port_snapshot_endpoints,
        to_jsonb(t) || jsonb_build_object('id', pg_temp.fixture_id(900)))).*
    FROM port_snapshot_endpoints t WHERE collection_run_id = pg_temp.fixture_id(112) $q$, '23505');

-- 当前授权/绑定/标签可先软删再重建；历史行仍可追踪且恢复旧行不能冲突覆盖新行。
INSERT INTO asset_tags(id, asset_id, key, value)
    VALUES (pg_temp.fixture_id(301), pg_temp.fixture_id(20), 'verification', 'old');
UPDATE asset_tags SET "delete" = true WHERE id = pg_temp.fixture_id(301);
INSERT INTO asset_tags(id, asset_id, key, value)
    VALUES (pg_temp.fixture_id(302), pg_temp.fixture_id(20), 'verification', 'new');
UPDATE role_bindings SET "delete" = true WHERE id = pg_temp.fixture_id(51);
INSERT INTO role_bindings(id, user_id, role_code, scope_kind)
    VALUES (pg_temp.fixture_id(303), pg_temp.fixture_id(50), 'admin', 'global');
UPDATE policy_bindings SET "delete" = true WHERE id = pg_temp.fixture_id(62);
INSERT INTO policy_bindings(id, policy_revision_id, scope_kind)
    VALUES (pg_temp.fixture_id(304), pg_temp.fixture_id(61), 'default');
SELECT pg_temp.assert_true('soft_deleted_tag_can_be_recreated',
    (SELECT count(*) FILTER (WHERE NOT "delete") = 1 AND count(*) FILTER (WHERE "delete") = 1
     FROM asset_tags WHERE asset_id = pg_temp.fixture_id(20) AND key = 'verification'));
SELECT pg_temp.assert_true('soft_deleted_role_binding_can_be_recreated',
    (SELECT count(*) FILTER (WHERE NOT "delete") = 1 AND count(*) FILTER (WHERE "delete") = 1
     FROM role_bindings WHERE user_id = pg_temp.fixture_id(50) AND role_code = 'admin' AND scope_kind = 'global'));
SELECT pg_temp.assert_true('soft_deleted_policy_binding_can_be_recreated',
    (SELECT count(*) FILTER (WHERE NOT "delete") = 1 AND count(*) FILTER (WHERE "delete") = 1
     FROM policy_bindings WHERE scope_kind = 'default'));
SELECT pg_temp.expect_error('restoring_tag_cannot_conflict_with_current_tag', $q$
    UPDATE asset_tags SET "delete" = false WHERE id = pg_temp.fixture_id(301) $q$, '23505');

-- 永久业务键不会因软删被释放，防止历史版本和投递去重绕过。
UPDATE asset_desired_states SET "delete" = true WHERE id = pg_temp.fixture_id(201);
UPDATE inbox_receipts SET "delete" = true WHERE id = pg_temp.fixture_id(206);
UPDATE package_entries SET "delete" = true WHERE id = pg_temp.fixture_id(207);
UPDATE vulnerability_package_coverage SET "delete" = true WHERE id = pg_temp.fixture_id(211);
SELECT pg_temp.expect_error('soft_deleted_desired_generation_still_unique', $q$
    INSERT INTO asset_desired_states
    SELECT (jsonb_populate_record(NULL::asset_desired_states,
        to_jsonb(t) || jsonb_build_object('id', pg_temp.fixture_id(900), 'delete', false))).*
    FROM asset_desired_states t WHERE id = pg_temp.fixture_id(201) $q$, '23505');
SELECT pg_temp.expect_error('soft_deleted_inbox_still_deduplicates', $q$
    INSERT INTO inbox_receipts
    SELECT (jsonb_populate_record(NULL::inbox_receipts,
        to_jsonb(t) || jsonb_build_object('id', pg_temp.fixture_id(900), 'delete', false))).*
    FROM inbox_receipts t WHERE id = pg_temp.fixture_id(206) $q$, '23505');
SELECT pg_temp.expect_error('soft_deleted_package_entry_still_unique', $q$
    INSERT INTO package_entries
    SELECT (jsonb_populate_record(NULL::package_entries,
        to_jsonb(t) || jsonb_build_object('id', pg_temp.fixture_id(900), 'delete', false))).*
    FROM package_entries t WHERE id = pg_temp.fixture_id(207) $q$, '23505');
SELECT pg_temp.expect_error('soft_deleted_package_coverage_still_unique', $q$
    INSERT INTO vulnerability_package_coverage
    SELECT (jsonb_populate_record(NULL::vulnerability_package_coverage,
        to_jsonb(t) || jsonb_build_object('id', pg_temp.fixture_id(900), 'delete', false))).*
    FROM vulnerability_package_coverage t WHERE id = pg_temp.fixture_id(211) $q$, '23505');
INSERT INTO tasks(id, asset_id, kind, origin, parameters_schema_version, parameters, not_before, deadline_at, state)
    VALUES (pg_temp.fixture_id(305), pg_temp.fixture_id(20), 'diagnostic', 'manual', 1, '{}', '2000-01-01Z', '2000-01-02Z', 'failed');
INSERT INTO task_attempts(id, task_id, asset_id, attempt_no, state, "delete")
    VALUES (pg_temp.fixture_id(306), pg_temp.fixture_id(305), pg_temp.fixture_id(20), 1, 'failed', true);
SELECT pg_temp.expect_error('soft_deleted_attempt_number_still_unique', $q$
    INSERT INTO task_attempts(id, task_id, asset_id, attempt_no, state)
    VALUES (pg_temp.fixture_id(900), pg_temp.fixture_id(305), pg_temp.fixture_id(20), 1, 'failed') $q$, '23505');

-- 在途互斥和仍有效的身份不能靠软删绕过。
SELECT pg_temp.expect_error('nonterminal_task_cannot_be_soft_deleted', $q$
    UPDATE tasks SET "delete" = true WHERE id = pg_temp.fixture_id(82) $q$, '23514');
SELECT pg_temp.expect_error('open_attempt_cannot_be_soft_deleted', $q$
    UPDATE task_attempts SET "delete" = true WHERE id = pg_temp.fixture_id(92) $q$, '23514');
SELECT pg_temp.expect_error('pending_outbox_cannot_be_soft_deleted', $q$
    UPDATE outbox_messages SET "delete" = true WHERE id = pg_temp.fixture_id(95) $q$, '23514');
SELECT pg_temp.expect_error('leased_outbox_cannot_be_soft_deleted', $q$
    UPDATE outbox_messages SET state = 'leased', lease_token = pg_temp.fixture_id(900),
        lease_until = '2000-01-02Z', "delete" = true WHERE id = pg_temp.fixture_id(95) $q$, '23514');
SELECT pg_temp.expect_error('active_installation_cannot_be_soft_deleted', $q$
    UPDATE scout_installations SET "delete" = true WHERE id = pg_temp.fixture_id(30) $q$, '23514');
SELECT pg_temp.expect_error('running_instance_cannot_be_soft_deleted', $q$
    UPDATE scout_instances SET "delete" = true WHERE id = pg_temp.fixture_id(42) $q$, '23514');
SELECT pg_temp.expect_error('unrevoked_credential_cannot_be_soft_deleted', $q$
    UPDATE scout_credentials SET "delete" = true WHERE id = pg_temp.fixture_id(52) $q$, '23514');
INSERT INTO vulnerability_evaluation_runs(id, asset_id, snapshot_id, intelligence_revision_id, matcher_revision, status, requested_at)
    VALUES (pg_temp.fixture_id(307), pg_temp.fixture_id(20), pg_temp.fixture_id(100), pg_temp.fixture_id(120), 'fixture', 'queued', '2000-01-01Z');
SELECT pg_temp.expect_error('queued_evaluation_cannot_be_soft_deleted', $q$
    UPDATE vulnerability_evaluation_runs SET "delete" = true WHERE id = pg_temp.fixture_id(307) $q$, '23514');
INSERT INTO assets(id, group_id, display_name)
    VALUES (pg_temp.fixture_id(308), pg_temp.fixture_id(10), 'verification_retirement');
SELECT pg_temp.expect_error('active_asset_cannot_be_soft_deleted', $q$
    UPDATE assets SET "delete" = true WHERE id = pg_temp.fixture_id(308) $q$, '23514');
UPDATE assets SET lifecycle = 'retired', retired_at = '2000-01-01Z', "delete" = true WHERE id = pg_temp.fixture_id(308);
SELECT pg_temp.assert_true('retired_asset_can_be_soft_deleted',
    (SELECT "delete" FROM assets WHERE id = pg_temp.fixture_id(308)));
UPDATE scout_credentials SET revoked_at = '2000-01-01Z', "delete" = true WHERE id = pg_temp.fixture_id(52);
SELECT pg_temp.assert_true('revoked_credential_can_be_soft_deleted',
    (SELECT "delete" FROM scout_credentials WHERE id = pg_temp.fixture_id(52)));

SELECT name, expected_sqlstate, actual_sqlstate, rejected_table, rejected_constraint
FROM pg_temp.sentinel_verification_results ORDER BY name;
SELECT count(*) AS passed_assertions,
       count(*) FILTER (WHERE expected_sqlstate = '00000') AS positive_assertions,
       count(*) FILTER (WHERE expected_sqlstate <> '00000') AS rejected_invalid_cases
FROM pg_temp.sentinel_verification_results;
ROLLBACK;
