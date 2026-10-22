//! Run against the dedicated local test database with TEST_DATABASE_URL=... cargo test -p hub --test ingestion -- --ignored.
use anyhow::{Context, Result};
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use chrono::Utc;
use ed25519_dalek::SigningKey;
use hub::{
    api::{AppState, router},
    db,
    ingest::{self, Outcome},
};
use sentinel_protocol::*;
use serde_json::{Value, json};
use sqlx::Row;
use std::sync::{Arc, atomic::AtomicBool};
use tower::ServiceExt;
use uuid::Uuid;
const TOKEN: &str = "fictional-test-administrator-token-only";
async fn call(
    state: &AppState,
    method: &str,
    path: &str,
    body: Value,
    auth: bool,
) -> Result<(StatusCode, Value)> {
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if auth {
        req = req.header("authorization", format!("Bearer {TOKEN}"));
    }
    let response = router(state.clone(), "/nonexistent".into())
        .oneshot(req.body(Body::from(serde_json::to_vec(&body)?))?)
        .await?;
    let status = response.status();
    let body = to_bytes(response.into_body(), 2_000_000).await?;
    Ok((status, serde_json::from_slice(&body)?))
}
fn event(asset: Uuid, installation: Uuid) -> Observation {
    Observation {
        queue_health: QueueHealth::default(),
        schema_version: 1,
        event_id: Uuid::new_v4(),
        asset_id: asset,
        installation_id: installation,
        instance_id: Uuid::new_v4(),
        active_epoch: 1,
        collection_sequence: 30,
        metric_sequence: 2,
        started_at: Utc::now(),
        observed_at: Utc::now(),
        scout_version: "fictional-test".into(),
        inventory_run_id: Uuid::new_v4(),
        packages_run_id: Uuid::new_v4(),
        ports_run_id: Uuid::new_v4(),
        host: Host {
            hostname: Some("fictional-host".into()),
            boot_id: Some(Uuid::new_v4()),
            ..Host::default()
        },
        metrics: Metrics {
            cpu_percent: Some(10.0),
            memory_total_bytes: Some(8192),
            memory_available_bytes: Some(4096),
            process_count: Some(0),
            ..Metrics::default()
        },
        interfaces: vec![],
        processes: vec![],
        ports: vec![],
        packages: vec![],
        coverage: [
            "host",
            "cpu",
            "memory",
            "network",
            "processes",
            "ports",
            "packages",
        ]
        .into_iter()
        .map(|s| {
            (
                s.into(),
                Coverage {
                    status: CoverageStatus::Complete,
                    reason: None,
                },
            )
        })
        .collect(),
    }
}
#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL TEST_DATABASE_URL"]
async fn signed_ingestion_dedup_order_auth_and_soft_delete() -> Result<()> {
    let url = std::env::var("TEST_DATABASE_URL").context("dedicated TEST_DATABASE_URL required")?;
    let pool = db::connect(&url).await?;
    db::migrate(&pool).await?;
    // Reopening after schema creation must reuse the public SQLx ledger.
    let reopened = db::connect(&url).await?;
    db::migrate(&reopened).await?;
    reopened.close().await;
    let (admin_id, default_group) = db::bootstrap(&pool).await?;
    let state = AppState {
        pool: pool.clone(),
        token_hash: hash(TOKEN.as_bytes()),
        admin_id,
        default_group,
        ready: Arc::new(AtomicBool::new(true)),
    };
    assert_eq!(
        call(&state, "GET", "/api/v1/assets", Value::Null, false)
            .await?
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(&state, "POST", "/api/v1/tasks", json!({}), true)
            .await?
            .0,
        StatusCode::NOT_IMPLEMENTED
    );
    let installation = Uuid::new_v4();
    let key = SigningKey::from_bytes(&hash(installation.as_bytes()));
    let enrollment = json!({"installation_id":installation,"public_key":hex::encode(key.verifying_key().to_bytes()),"display_name":"Fictional integration asset"});
    let (status, registered) = call(
        &state,
        "POST",
        "/api/v1/installations",
        enrollment.clone(),
        true,
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    let asset: Uuid = serde_json::from_value(registered["asset_id"].clone())?;
    assert_eq!(
        call(&state, "POST", "/api/v1/installations", enrollment, true)
            .await?
            .1["asset_id"],
        json!(asset)
    );
    let mut e = event(asset, installation);
    e.host.fingerprint_sha256 = Some(hex::encode(hash(installation.as_bytes())));
    e.coverage.insert(
        "host".into(),
        Coverage {
            status: CoverageStatus::Partial,
            reason: Some("fixture partial coverage".into()),
        },
    );
    let signed = SignedEvent::sign(&e, &key)?;
    assert_eq!(
        ingest::accept(&pool, &e.subject(), &signed).await?,
        Outcome::Applied
    );
    assert_eq!(
        ingest::accept(&pool, &e.subject(), &signed).await?,
        Outcome::Duplicate
    );
    let mut tampered: SignedEvent = serde_json::from_slice(&signed)?;
    tampered.payload.push(' ');
    assert!(
        ingest::accept(&pool, &e.subject(), &serde_json::to_vec(&tampered)?)
            .await
            .is_err()
    );
    assert!(
        ingest::accept(&pool, "sentinel.events.wrong", &signed)
            .await
            .is_err()
    );
    let mut conflict = e.clone();
    conflict.metrics.cpu_percent = Some(99.0);
    assert!(
        ingest::accept(&pool, &e.subject(), &SignedEvent::sign(&conflict, &key)?)
            .await
            .is_err()
    );
    let mut forged = e.clone();
    forged.asset_id = Uuid::new_v4();
    forged.event_id = Uuid::new_v4();
    assert!(
        ingest::accept(&pool, &e.subject(), &SignedEvent::sign(&forged, &key)?)
            .await
            .is_err()
    );
    // A late complete observation advances only the complete pointer; metrics and latest attempt stay newer.
    let mut older = e.clone();
    older.event_id = Uuid::new_v4();
    older.inventory_run_id = Uuid::new_v4();
    older.packages_run_id = Uuid::new_v4();
    older.ports_run_id = Uuid::new_v4();
    older.collection_sequence = 27;
    older.metric_sequence = 1;
    older.metrics.cpu_percent = Some(3.0);
    older.coverage.insert(
        "host".into(),
        Coverage {
            status: CoverageStatus::Complete,
            reason: None,
        },
    );
    assert_eq!(
        ingest::accept(&pool, &older.subject(), &SignedEvent::sign(&older, &key)?).await?,
        Outcome::Applied
    );
    let head=sqlx::query("SELECT latest_attempt_id,latest_complete_id FROM sentinel.asset_collection_heads WHERE asset_id=$1 AND kind='inventory'").bind(asset).fetch_one(&pool).await?;
    assert_eq!(head.get::<Uuid, _>("latest_attempt_id"), e.inventory_run_id);
    assert_eq!(
        head.get::<Uuid, _>("latest_complete_id"),
        older.inventory_run_id
    );
    let cpu: f64 = sqlx::query_scalar(
        "SELECT cpu_percent::float8 FROM sentinel.asset_metric_latest WHERE asset_id=$1",
    )
    .bind(asset)
    .fetch_one(&pool)
    .await?;
    assert_eq!(cpu, 10.0);
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM sentinel.inbox_receipts WHERE asset_id=$1")
            .bind(asset)
            .fetch_one(&pool)
            .await?;
    assert_eq!(count, 2);
    let detail = call(
        &state,
        "GET",
        &format!("/api/v1/assets/{asset}"),
        Value::Null,
        true,
    )
    .await?;
    assert_eq!(detail.0, StatusCode::OK);
    assert_eq!(detail.1["inventory"]["hostname"], "fictional-host");
    // Soft deletion never releases inbox uniqueness.
    sqlx::query("UPDATE sentinel.inbox_receipts SET \"delete\"=true WHERE asset_id=$1")
        .bind(asset)
        .execute(&pool)
        .await?;
    assert_eq!(
        ingest::accept(&pool, &e.subject(), &signed).await?,
        Outcome::Duplicate
    );
    // Same derived fingerprint is an investigation clue, never an identity merge.
    let other_installation = Uuid::new_v4();
    let other_key = SigningKey::from_bytes(&hash(other_installation.as_bytes()));
    let other_registration=call(&state,"POST","/api/v1/installations",json!({"installation_id":other_installation,"public_key":hex::encode(other_key.verifying_key().to_bytes()),"display_name":"Fictional cloned fingerprint"}),true).await?.1;
    let other_asset: Uuid = serde_json::from_value(other_registration["asset_id"].clone())?;
    assert_ne!(asset, other_asset);
    let mut other_event = event(other_asset, other_installation);
    other_event.host.fingerprint_sha256 = e.host.fingerprint_sha256.clone();
    ingest::accept(
        &pool,
        &other_event.subject(),
        &SignedEvent::sign(&other_event, &other_key)?,
    )
    .await?;
    let conflicts = call(
        &state,
        "GET",
        &format!("/api/v1/assets/{asset}"),
        Value::Null,
        true,
    )
    .await?
    .1;
    assert_eq!(
        conflicts["identity_conflicts"]
            .as_array()
            .context("conflict array")?
            .len(),
        1
    );
    // The new typed process table retains the cross-asset foreign-key boundary.
    assert!(sqlx::query("INSERT INTO sentinel.process_snapshot_entries(id,collection_run_id,asset_id,pid,start_ticks,name,state) VALUES($1,$2,$3,1,1,'fictional','R')").bind(Uuid::new_v4()).bind(e.inventory_run_id).bind(other_asset).execute(&pool).await.is_err());
    assert_eq!(
        call(
            &state,
            "POST",
            &format!("/api/v1/installations/{installation}/revoke"),
            json!({}),
            true
        )
        .await?
        .0,
        StatusCode::OK
    );
    assert!(ingest::accept(&pool, &e.subject(), &signed).await.is_err());
    pool.close().await;
    Ok(())
}
