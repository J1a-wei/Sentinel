use anyhow::{Context, Result, bail, ensure};
use chrono::{Duration, Utc};
use sentinel_protocol::{HANDLER, Observation, SignedEvent, hash};
use serde_json::json;
use sqlx::{PgPool, Postgres, QueryBuilder, Row, Transaction};
use uuid::Uuid;

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Applied,
    Historical,
    Duplicate,
}
/// All domain changes and the inbox receipt commit together. The caller may ACK only after Ok.
pub async fn accept(pool: &PgPool, subject: &str, bytes: &[u8]) -> Result<Outcome> {
    let (event, key_hash, payload_hash) = SignedEvent::verify(bytes)?;
    ensure!(subject == event.subject(), "subject_identity_mismatch");
    let mut tx = pool.begin().await?;
    let generation=sqlx::query_scalar::<_,i64>(r#"SELECT i.generation FROM scout_installations i JOIN assets a ON a.id=i.asset_id JOIN asset_groups g ON g.id=a.group_id WHERE i.id=$1 AND i.asset_id=$2 AND i.status='active' AND NOT i."delete" AND NOT a."delete" AND a.lifecycle='active' AND NOT g."delete" AND EXISTS(SELECT 1 FROM scout_credentials c WHERE c.installation_id=i.id AND c.public_key_sha256=$3 AND c.issuer_reference='sentinel:ed25519:v1' AND NOT c."delete" AND c.revoked_at IS NULL AND c.valid_from<=now() AND c.valid_until>now()) FOR UPDATE OF i,a"#)
        .bind(event.installation_id).bind(event.asset_id).bind(key_hash.to_vec()).fetch_optional(&mut *tx).await?.context("unauthorized_installation")?;
    if let Some(old)=sqlx::query_scalar::<_,Vec<u8>>("SELECT payload_sha256 FROM inbox_receipts WHERE handler_key=$1 AND producer_installation_id=$2 AND event_id=$3")
        .bind(HANDLER).bind(event.installation_id).bind(event.event_id).fetch_optional(&mut *tx).await? {
        ensure!(old==payload_hash,"event_id_payload_conflict");
        tx.commit().await?; return Ok(Outcome::Duplicate);
    }
    ensure!(
        event.observed_at <= Utc::now() + Duration::minutes(5)
            && event.observed_at >= Utc::now() - Duration::days(7),
        "observation_outside_replay_window"
    );
    let current = register_instance(&mut tx, &event).await?;
    fingerprint(&mut tx, &event).await?;
    let package_snapshot = packages(&mut tx, &event).await?;
    let inventory_complete = event.complete(&["host", "network", "processes"]);
    let package_complete = event.complete(&["packages"]);
    let port_complete = event.complete(&["ports"]);
    for (id, kind, seq, complete, snapshot) in [
        (
            event.inventory_run_id,
            "inventory",
            event.collection_sequence,
            inventory_complete,
            None,
        ),
        (
            event.packages_run_id,
            "packages",
            event.collection_sequence + 1,
            package_complete,
            Some(package_snapshot),
        ),
        (
            event.ports_run_id,
            "ports",
            event.collection_sequence + 2,
            port_complete,
            None,
        ),
    ] {
        let status = if complete { "complete" } else { "partial" };
        sqlx::query("INSERT INTO collection_runs(id,asset_id,installation_id,instance_id,active_epoch,sequence,kind,status,schema_version,collector_revision,package_snapshot_id,expected_scope,coverage,started_at,finished_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,1,$9,$10,$11,$12,$13,$14)")
            .bind(id).bind(event.asset_id).bind(event.installation_id).bind(event.instance_id).bind(event.active_epoch).bind(seq).bind(kind).bind(status).bind(&event.scout_version).bind(snapshot)
            .bind(json!({"scope":"host","kind":kind})).bind(json!(event.coverage)).bind(event.started_at).bind(event.observed_at).execute(&mut *tx).await?;
        if current {
            head(&mut tx, &event, id, kind, seq, generation, complete).await?;
        }
    }
    sqlx::query("INSERT INTO asset_inventory_snapshots(id,collection_run_id,asset_id,hostname,os_id,os_version,kernel_version,architecture,cpu_model,logical_cpu_count,memory_total_bytes,boot_id,interfaces) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)")
        .bind(Uuid::new_v4()).bind(event.inventory_run_id).bind(event.asset_id).bind(&event.host.hostname).bind(&event.host.os_id).bind(&event.host.os_version).bind(&event.host.kernel_version).bind(&event.host.architecture).bind(&event.host.cpu_model).bind(event.host.logical_cpu_count).bind(event.metrics.memory_total_bytes).bind(event.host.boot_id).bind(json!(event.interfaces)).execute(&mut *tx).await?;
    for chunk in event.processes.chunks(500) {
        let mut q = QueryBuilder::<Postgres>::new(
            "INSERT INTO process_snapshot_entries(id,collection_run_id,asset_id,pid,start_ticks,name,state) ",
        );
        q.push_values(chunk, |mut b, p| {
            b.push_bind(Uuid::new_v4())
                .push_bind(event.inventory_run_id)
                .push_bind(event.asset_id)
                .push_bind(p.pid)
                .push_bind(p.start_ticks)
                .push_bind(&p.name)
                .push_bind(&p.state);
        });
        q.build().execute(&mut *tx).await?;
    }
    for chunk in event.ports.chunks(500) {
        // inet is deliberately cast from a validated IpAddr, never interpolated SQL.
        let mut q = QueryBuilder::<Postgres>::new(
            "INSERT INTO port_snapshot_endpoints(id,collection_run_id,asset_id,network_namespace,protocol,local_address,local_port) ",
        );
        q.push_values(chunk, |mut b, p| {
            b.push_bind(Uuid::new_v4())
                .push_bind(event.ports_run_id)
                .push_bind(event.asset_id)
                .push_bind(&p.network_namespace)
                .push_bind(&p.protocol)
                .push_bind(p.address.to_string())
                .push_unseparated("::inet")
                .push_bind(i32::from(p.port));
        });
        q.build().execute(&mut *tx).await?;
    }
    if current {
        metrics(&mut tx, &event).await?;
    }
    sqlx::query("INSERT INTO inbox_receipts(id,handler_key,producer_installation_id,event_id,asset_id,producer_instance_id,payload_sha256) VALUES($1,$2,$3,$4,$5,$6,$7)")
        .bind(Uuid::new_v4()).bind(HANDLER).bind(event.installation_id).bind(event.event_id).bind(event.asset_id).bind(event.instance_id).bind(payload_hash.to_vec()).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(if current {
        Outcome::Applied
    } else {
        Outcome::Historical
    })
}
async fn register_instance(tx: &mut Transaction<'_, Postgres>, e: &Observation) -> Result<bool> {
    if let Some(row)=sqlx::query("SELECT asset_id,installation_id,active_epoch,role,\"delete\" FROM scout_instances WHERE id=$1").bind(e.instance_id).fetch_optional(&mut **tx).await? {
        ensure!(row.get::<Uuid,_>("asset_id")==e.asset_id && row.get::<Uuid,_>("installation_id")==e.installation_id && row.get::<Option<i64>,_>("active_epoch")==Some(e.active_epoch) && !row.get::<bool,_>("delete"),"instance_binding_conflict");
        sqlx::query("UPDATE scout_instances SET last_seen_at=now() WHERE id=$1").bind(e.instance_id).execute(&mut **tx).await?;
        return Ok(row.get::<String,_>("role")=="active");
    }
    let max: Option<i64> = sqlx::query_scalar(
        "SELECT max(active_epoch) FROM scout_instances WHERE installation_id=$1",
    )
    .bind(e.installation_id)
    .fetch_one(&mut **tx)
    .await?;
    if max == Some(e.active_epoch) {
        bail!("identity_epoch_conflict");
    }
    let current = max.is_none_or(|max| e.active_epoch > max);
    if current {
        sqlx::query("UPDATE scout_instances SET role='exited',ended_at=now() WHERE asset_id=$1 AND role='active'").bind(e.asset_id).execute(&mut **tx).await?;
    }
    sqlx::query("INSERT INTO scout_instances(id,asset_id,installation_id,role,version,boot_id,active_epoch,started_at,ended_at,capabilities) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)")
        .bind(e.instance_id).bind(e.asset_id).bind(e.installation_id).bind(if current {"active"} else {"exited"}).bind(&e.scout_version).bind(e.host.boot_id).bind(e.active_epoch).bind(e.started_at).bind(if current {None} else {Some(e.observed_at)})
        .bind(json!({"read_only":true,"inventory":true,"remote_execution":false})).execute(&mut **tx).await?;
    Ok(current)
}
async fn packages(tx: &mut Transaction<'_, Postgres>, e: &Observation) -> Result<Uuid> {
    let mut entries = e.packages.clone();
    entries.sort_by(|a, b| (&a.name, &a.architecture).cmp(&(&b.name, &b.architecture)));
    let digest = hash(&serde_json::to_vec(&(
        1,
        &e.host.os_id,
        &e.host.os_version,
        &e.host.architecture,
        &entries,
    ))?);
    if let Some(row) = sqlx::query(
        "SELECT id,\"delete\" FROM package_snapshots WHERE asset_id=$1 AND content_sha256=$2",
    )
    .bind(e.asset_id)
    .bind(digest.to_vec())
    .fetch_optional(&mut **tx)
    .await?
    {
        ensure!(!row.get::<bool, _>("delete"), "package_snapshot_deleted");
        return Ok(row.get("id"));
    }
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO package_snapshots(id,asset_id,content_sha256,schema_version,os_id,os_version,architecture,package_count) VALUES($1,$2,$3,1,$4,$5,$6,$7)")
        .bind(id).bind(e.asset_id).bind(digest.to_vec()).bind(e.host.os_id.as_deref().unwrap_or("unknown")).bind(e.host.os_version.as_deref().unwrap_or("unknown")).bind(e.host.architecture.as_deref().unwrap_or("unknown")).bind(i32::try_from(entries.len())?).execute(&mut **tx).await?;
    for chunk in entries.chunks(500) {
        let mut q = QueryBuilder::<Postgres>::new(
            "INSERT INTO package_entries(id,snapshot_id,package_name,architecture,version,source_name,source_version,origin_status) ",
        );
        q.push_values(chunk, |mut b, p| {
            b.push_bind(Uuid::new_v4())
                .push_bind(id)
                .push_bind(&p.name)
                .push_bind(&p.architecture)
                .push_bind(&p.version)
                .push_bind(&p.source_name)
                .push_bind(&p.source_version)
                .push_bind(&p.origin);
        });
        q.build().execute(&mut **tx).await?;
    }
    Ok(id)
}
#[allow(clippy::too_many_arguments)]
async fn head(
    tx: &mut Transaction<'_, Postgres>,
    e: &Observation,
    id: Uuid,
    kind: &str,
    seq: i64,
    generation: i64,
    complete: bool,
) -> Result<()> {
    let old=sqlx::query(r#"SELECT h."delete",r.sequence AS attempt_seq,si.generation AS attempt_gen,c.sequence AS complete_seq,ci.generation AS complete_gen FROM asset_collection_heads h JOIN collection_runs r ON r.id=h.latest_attempt_id JOIN scout_installations si ON si.id=r.installation_id LEFT JOIN collection_runs c ON c.id=h.latest_complete_id LEFT JOIN scout_installations ci ON ci.id=c.installation_id WHERE h.asset_id=$1 AND h.kind=$2 AND h.scope_key='host'"#).bind(e.asset_id).bind(kind).fetch_optional(&mut **tx).await?;
    if let Some(row) = old {
        ensure!(!row.get::<bool, _>("delete"), "head_deleted");
        let attempt = (generation, seq)
            > (
                row.get::<i64, _>("attempt_gen"),
                row.get::<i64, _>("attempt_seq"),
            );
        let full = complete
            && match (
                row.get::<Option<i64>, _>("complete_gen"),
                row.get::<Option<i64>, _>("complete_seq"),
            ) {
                (Some(g), Some(s)) => (generation, seq) > (g, s),
                _ => true,
            };
        if attempt || full {
            sqlx::query("UPDATE asset_collection_heads SET latest_attempt_id=CASE WHEN $4 THEN $3 ELSE latest_attempt_id END,latest_complete_id=CASE WHEN $5 THEN $3 ELSE latest_complete_id END WHERE asset_id=$1 AND kind=$2 AND scope_key='host'")
                .bind(e.asset_id).bind(kind).bind(id).bind(attempt).bind(full).execute(&mut **tx).await?;
        }
    } else {
        sqlx::query("INSERT INTO asset_collection_heads(id,asset_id,kind,scope_key,latest_attempt_id,latest_complete_id) VALUES($1,$2,$3,'host',$4,$5)")
            .bind(Uuid::new_v4()).bind(e.asset_id).bind(kind).bind(id).bind(if complete {Some(id)} else {None}).execute(&mut **tx).await?;
    }
    Ok(())
}
async fn metrics(tx: &mut Transaction<'_, Postgres>, e: &Observation) -> Result<()> {
    let Some(boot) = e.host.boot_id else {
        return Ok(());
    };
    let m = &e.metrics;
    sqlx::query(r#"INSERT INTO asset_metric_latest(id,asset_id,installation_id,instance_id,active_epoch,sequence,boot_id,observed_at,cpu_percent,memory_total_bytes,memory_available_bytes,process_count,running_process_count,zombie_process_count,load1,swap_used_bytes,resource_summary,scout_health,quality)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::float8::numeric,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
        ON CONFLICT(asset_id) DO UPDATE SET installation_id=excluded.installation_id,instance_id=excluded.instance_id,active_epoch=excluded.active_epoch,sequence=excluded.sequence,boot_id=excluded.boot_id,observed_at=excluded.observed_at,received_at=now(),cpu_percent=excluded.cpu_percent,memory_total_bytes=excluded.memory_total_bytes,memory_available_bytes=excluded.memory_available_bytes,process_count=excluded.process_count,running_process_count=excluded.running_process_count,zombie_process_count=excluded.zombie_process_count,load1=excluded.load1,swap_used_bytes=excluded.swap_used_bytes,resource_summary=excluded.resource_summary,scout_health=excluded.scout_health,quality=excluded.quality
        WHERE NOT asset_metric_latest."delete" AND (asset_metric_latest.installation_id<>excluded.installation_id OR asset_metric_latest.sequence<excluded.sequence)"#)
        .bind(Uuid::new_v4()).bind(e.asset_id).bind(e.installation_id).bind(e.instance_id).bind(e.active_epoch).bind(e.metric_sequence).bind(boot).bind(e.observed_at).bind(m.cpu_percent).bind(m.memory_total_bytes).bind(m.memory_available_bytes).bind(m.process_count).bind(m.running_process_count).bind(m.zombie_process_count).bind(m.load1).bind(m.swap_used_bytes)
        .bind(json!({"interfaces":e.interfaces})).bind(json!({"version":e.scout_version,"read_only":true,"queue":e.queue_health})).bind(json!(e.coverage)).execute(&mut **tx).await?;
    Ok(())
}

async fn fingerprint(tx: &mut Transaction<'_, Postgres>, e: &Observation) -> Result<()> {
    let Some(value) = &e.host.fingerprint_sha256 else {
        return Ok(());
    };
    let digest = hex::decode(value)?;
    // Serialize equal fingerprints without ever using one as authentication or an asset key.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(value)
        .execute(&mut **tx)
        .await?;
    let others:Vec<Uuid>=sqlx::query_scalar(r#"SELECT DISTINCT f.asset_id FROM asset_fingerprint_observations f JOIN assets a ON a.id=f.asset_id AND NOT a."delete" WHERE f.algorithm_revision='sentinel:machine-id:v1' AND f.fingerprint_sha256=$1 AND f.asset_id<>$2 AND NOT f."delete" LIMIT 100"#).bind(&digest).bind(e.asset_id).fetch_all(&mut **tx).await?;
    sqlx::query("INSERT INTO asset_fingerprint_observations(id,asset_id,instance_id,algorithm_revision,fingerprint_sha256,observed_at) VALUES($1,$2,$3,'sentinel:machine-id:v1',$4,$5)").bind(Uuid::new_v4()).bind(e.asset_id).bind(e.instance_id).bind(&digest).bind(e.observed_at).execute(&mut **tx).await?;
    for other in others {
        sqlx::query(r#"INSERT INTO identity_conflicts(id,asset_id,other_asset_id,reason_code,evidence) SELECT $1,$2,$3,'matching_fingerprint','{"algorithm":"sentinel:machine-id:v1","disposition":"unresolved_no_merge"}'::jsonb WHERE NOT EXISTS(SELECT 1 FROM identity_conflicts WHERE state='open' AND NOT "delete" AND reason_code='matching_fingerprint' AND ((asset_id=$2 AND other_asset_id=$3) OR (asset_id=$3 AND other_asset_id=$2)))"#).bind(Uuid::new_v4()).bind(e.asset_id).bind(other).execute(&mut **tx).await?;
    }
    Ok(())
}
