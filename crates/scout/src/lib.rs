mod adapter;
mod budget;
pub mod collectors;
mod runtime_env;
pub mod state;
use anyhow::{Context, Result, ensure};
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;
use state::LocalState;
use std::{
    env,
    path::PathBuf,
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

pub async fn run() -> Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_writer(std::io::stderr)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let command = env::args().nth(1).unwrap_or_default();
    ensure!(
        ["", "init", "enroll", "once", "status", "doctor"].contains(&command.as_str()),
        "usage: scout [init|enroll|once|status|doctor]"
    );
    if command == "doctor" {
        let report = runtime_env::inspect_current().await?;
        println!("{}", serde_json::to_string(&report)?);
        return report.require_collection();
    }
    let path =
        PathBuf::from(env::var("SENTINEL_STATE_DIR").unwrap_or_else(|_| "./var/scout".into()));
    if command == "status" {
        println!(
            "{}",
            serde_json::to_string(&state::read_status(&path).await?)?
        );
        return Ok(());
    }
    // Resolve collection sources before opening mutable state. Init/enroll and
    // the compatible status command do not depend on collection configuration.
    let runtime = if command.is_empty() || command == "once" {
        let report = runtime_env::inspect_current().await?;
        tracing::info!(detected_runtime = ?report.detected_runtime,
            selected_mode = ?report.selected_mode, host_root = ?report.host_root,
            network_source = ?report.network_source, reasons = ?report.reasons,
            "Scout runtime and collection sources selected");
        report.require_collection()?;
        Some(report)
    } else {
        None
    };
    let mut state = LocalState::open(&path).await?;
    if command == "init" {
        println!(
            "{}",
            json!({"installation_id":state.identity.installation_id,"asset_id":state.identity.asset_id,"public_key":hex::encode(state.identity.key.verifying_key().to_bytes()),"queue":state.health().await?})
        );
        return Ok(());
    }
    if command == "enroll" {
        let token = sentinel_protocol::secret("SENTINEL_ADMIN_TOKEN")?
            .context("administrator credential required for enrollment")?;
        ensure!(
            token.len() >= 32,
            "administrator credential must be at least 32 characters"
        );
        let url = env::var("SENTINEL_HUB_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".into());
        let group = env::var("SENTINEL_GROUP_ID")
            .ok()
            .map(|s| s.parse::<Uuid>())
            .transpose()
            .context("invalid group ID")?;
        let response=reqwest::Client::builder().timeout(Duration::from_secs(15)).redirect(reqwest::redirect::Policy::none()).build()?
            .post(format!("{}/api/v1/installations",url.trim_end_matches('/'))).bearer_auth(token)
            .json(&json!({"installation_id":state.identity.installation_id,"public_key":hex::encode(state.identity.key.verifying_key().to_bytes()),"display_name":env::var("SENTINEL_ASSET_NAME").unwrap_or_else(|_|format!("Scout {}",state.identity.installation_id)),"group_id":group}))
            .send().await.context("enrollment request failed")?;
        ensure!(
            response.status().is_success(),
            "enrollment rejected with HTTP {}",
            response.status()
        );
        #[derive(Deserialize)]
        struct Enrollment {
            asset_id: Uuid,
            installation_id: Uuid,
        }
        let response: Enrollment = response
            .json()
            .await
            .context("invalid enrollment response")?;
        ensure!(
            response.installation_id == state.identity.installation_id,
            "enrollment identity mismatch"
        );
        state.bind(response.asset_id).await?;
        println!(
            "{}",
            json!({"asset_id":response.asset_id,"installation_id":response.installation_id})
        );
        return Ok(());
    }
    let asset_id = state
        .identity
        .asset_id
        .context("Scout is not enrolled; run scout enroll first")?;
    let interval = env::var("SENTINEL_INTERVAL_SECONDS")
        .unwrap_or_else(|_| "30".into())
        .parse::<u64>()
        .context("invalid collection interval")?;
    ensure!(
        (5..=3600).contains(&interval),
        "collection interval must be 5..3600 seconds"
    );
    let runtime = runtime.context("collection runtime was not selected")?;
    let host_root = runtime
        .host_root
        .context("collection root was not selected")?;
    let network_proc_prefix = runtime.network_proc_prefix;
    let nats_url = env::var("SENTINEL_NATS_URL").unwrap_or_else(|_| "nats://127.0.0.1:4222".into());
    let nats_token = sentinel_protocol::secret("SENTINEL_NATS_TOKEN")?;
    let instance = Uuid::new_v4();
    let epoch = state.new_epoch().await?;
    let stop = CancellationToken::new();
    let signal_stop = stop.clone();
    let signal = tokio::spawn(async move {
        shutdown_signal().await;
        signal_stop.cancel();
    });
    let mut previous = None;
    loop {
        let started = Utc::now();
        let monotonic = Instant::now();
        let root = host_root.clone();
        let network_proc_prefix = network_proc_prefix.clone();
        let mut task = tokio::task::spawn_blocking(move || {
            collectors::collect_with_options(
                &root,
                &collectors::CollectOptions {
                    max_processes: 8000,
                    max_file_bytes: 1024 * 1024,
                    max_dpkg_status_bytes: 32 * 1024 * 1024,
                    network_proc_prefix,
                    ..Default::default()
                },
            )
        });
        let batch = tokio::select! {
            _=stop.cancelled()=>break,
            result=tokio::time::timeout(Duration::from_secs(20),&mut task)=>result.context("collection deadline exceeded")?.context("collector worker stopped")?,
        };
        let (mut observation, sample) = adapter::convert(batch, previous.as_ref(), monotonic)?;
        observation.asset_id = asset_id;
        observation.installation_id = state.identity.installation_id;
        observation.instance_id = instance;
        observation.active_epoch = epoch;
        observation.started_at = started;
        observation.observed_at = Utc::now();
        previous = Some(sample);
        let stored = state.enqueue(observation).await?;
        let flushed = tokio::time::timeout(
            Duration::from_secs(12),
            flush(&state, &nats_url, nats_token.clone()),
        )
        .await;
        if !matches!(flushed, Ok(Ok(()))) {
            tracing::warn!(
                error_kind = "publish_pending",
                "JetStream unavailable or unconfirmed; pending events retained"
            );
        }
        if command == "once" {
            let health = state.health().await?;
            println!(
                "{}",
                json!({"collected":stored,"published":stored && health.pending_events==0,"queue":health})
            );
            ensure!(stored, "queue full; no observation enqueued");
            break;
        }
        tokio::select! {_=stop.cancelled()=>break,_=tokio::time::sleep(Duration::from_secs(interval))=>{}}
    }
    signal.abort();
    state.pool.close().await;
    Ok(())
}
async fn flush(state: &LocalState, url: &str, token: Option<String>) -> Result<()> {
    let mut options = async_nats::ConnectOptions::new().connection_timeout(Duration::from_secs(4));
    if let Some(token) = token {
        options = options.token(token);
    }
    let client = options
        .connect(url)
        .await
        .map_err(|_| anyhow::anyhow!("NATS connection unavailable"))?;
    let js = async_nats::jetstream::new(client);
    for _ in 0..100 {
        let Some((id, subject, payload)) = state.next().await? else {
            break;
        };
        let mut headers = async_nats::HeaderMap::new();
        headers.insert("Nats-Msg-Id", id.as_str());
        let ack = js
            .publish_with_headers(subject, headers, payload.into())
            .await
            .map_err(|_| anyhow::anyhow!("publish failed"))?;
        let confirmation = tokio::time::timeout(Duration::from_secs(5), ack)
            .await
            .context("publish confirmation timeout")?
            .map_err(|_| anyhow::anyhow!("publish not confirmed"))?;
        ensure!(
            confirmation.stream == sentinel_protocol::STREAM,
            "unexpected acknowledgement stream"
        );
        state.acknowledge(&id).await?;
    }
    Ok(())
}
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        if let Ok(mut term) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! {_=tokio::signal::ctrl_c()=>{},_=term.recv()=>{}};
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}
