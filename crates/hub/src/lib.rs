pub mod api;
mod config;
mod consumer;
pub mod db;
pub mod ingest;
use anyhow::{Context, Result};
use std::{
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

pub async fn run() -> Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let command = std::env::args().nth(1).unwrap_or_default();
    if command == "health" {
        let bind = std::env::var("SENTINEL_BIND").unwrap_or_else(|_| "127.0.0.1:8080".into());
        let addr: std::net::SocketAddr = bind.parse().context("invalid bind")?;
        let ip = if addr.ip().is_unspecified() {
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        } else {
            addr.ip()
        };
        reqwest::Client::builder()
            .timeout(Duration::from_secs(4))
            .build()?
            .get(format!(
                "http://{}/readyz",
                std::net::SocketAddr::new(ip, addr.port())
            ))
            .send()
            .await?
            .error_for_status()?;
        return Ok(());
    }
    anyhow::ensure!(
        command.is_empty() || command == "migrate",
        "usage: hub [migrate|health]"
    );
    let config = config::Config::load()?;
    let pool = db::connect(&config.database_url)
        .await
        .context("connect PostgreSQL")?;
    db::migrate(&pool).await.context("migrate PostgreSQL")?;
    if command == "migrate" {
        return Ok(());
    }
    let (admin_id, default_group) = db::bootstrap(&pool).await?;
    let ready = Arc::new(AtomicBool::new(false));
    let state = api::AppState {
        pool: pool.clone(),
        token_hash: sentinel_protocol::hash(config.admin_token.as_bytes()),
        admin_id,
        default_group,
        ready: ready.clone(),
    };
    let shutdown = CancellationToken::new();
    let consumer_stop = shutdown.clone();
    let worker = tokio::spawn(consumer::run(
        pool.clone(),
        config.nats_url,
        config.nats_token,
        ready,
        consumer_stop,
    ));
    let listener = tokio::net::TcpListener::bind(config.bind)
        .await
        .context("bind Hub")?;
    tracing::info!(address = %config.bind, "Hub listening; development administrator authentication enabled");
    let signal_stop = shutdown.clone();
    let signal = tokio::spawn(async move {
        shutdown_signal().await;
        signal_stop.cancel();
    });
    let result = axum::serve(listener, api::router(state, config.web_dir))
        .with_graceful_shutdown(shutdown.clone().cancelled_owned())
        .await;
    shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(20), worker).await;
    signal.abort();
    pool.close().await;
    result.context("serve Hub")
}
pub async fn shutdown_signal() {
    #[cfg(unix)]
    {
        if let Ok(mut term) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}
