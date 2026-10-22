use crate::ingest;
use anyhow::{Result, anyhow};
use async_nats::jetstream::{
    self, AckKind,
    consumer::{AckPolicy, pull},
    stream::{Config, DiscardPolicy, StorageType},
};
use futures_util::StreamExt;
use sentinel_protocol::{HANDLER, MAX_MESSAGE_BYTES, STREAM};
use sqlx::PgPool;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio_util::sync::CancellationToken;

pub async fn run(
    pool: PgPool,
    url: String,
    token: Option<String>,
    ready: Arc<AtomicBool>,
    stop: CancellationToken,
) {
    loop {
        if stop.is_cancelled() {
            break;
        }
        if consume(&pool, &url, token.clone(), &ready, &stop)
            .await
            .is_err()
        {
            tracing::warn!(
                error_kind = "nats_consumer",
                "message consumer disconnected; retrying"
            );
        }
        ready.store(false, Ordering::Relaxed);
        tokio::select! { _=stop.cancelled()=>break, _=tokio::time::sleep(Duration::from_secs(3))=>{} }
    }
}
async fn consume(
    pool: &PgPool,
    url: &str,
    token: Option<String>,
    ready: &AtomicBool,
    stop: &CancellationToken,
) -> Result<()> {
    let mut options = async_nats::ConnectOptions::new().connection_timeout(Duration::from_secs(5));
    if let Some(token) = token {
        options = options.token(token);
    }
    let client = options
        .connect(url)
        .await
        .map_err(|_| anyhow!("nats_connection"))?;
    let js = jetstream::new(client.clone());
    let stream = js
        .get_or_create_stream(Config {
            name: STREAM.into(),
            subjects: vec!["sentinel.events.*".into()],
            storage: StorageType::File,
            max_messages: 100_000,
            max_bytes: 512 * 1024 * 1024,
            max_message_size: MAX_MESSAGE_BYTES as i32,
            max_age: Duration::from_secs(7 * 86400),
            discard: DiscardPolicy::New,
            duplicate_window: Duration::from_secs(120),
            ..Default::default()
        })
        .await?;
    let consumer = stream
        .get_or_create_consumer(
            HANDLER,
            pull::Config {
                durable_name: Some(HANDLER.into()),
                filter_subject: "sentinel.events.*".into(),
                ack_policy: AckPolicy::Explicit,
                ack_wait: Duration::from_secs(60),
                max_ack_pending: 32,
                ..Default::default()
            },
        )
        .await?;
    let mut messages = consumer
        .stream()
        .max_messages_per_batch(1)
        .messages()
        .await?;
    ready.store(true, Ordering::Relaxed);
    let mut heartbeat = tokio::time::interval(Duration::from_secs(5));
    loop {
        tokio::select! {
            _=stop.cancelled()=>return Ok(()),
            _=heartbeat.tick()=> { ready.store(client.connection_state()==async_nats::connection::State::Connected,Ordering::Relaxed); },
            message=messages.next()=> {
                let Some(message)=message else { return Err(anyhow!("consumer_ended")); };
                let message=message?;
                let result=tokio::time::timeout(Duration::from_secs(45),ingest::accept(pool,message.subject.as_str(),&message.payload)).await;
                match result {
                    Ok(Ok(outcome))=> {
                        message.double_ack().await.map_err(|_|anyhow!("ack_failed"))?;
                        tracing::debug!(?outcome,"observation committed");
                    },
                    Ok(Err(error)) if permanent(&error)=> {
                        message.ack_with(AckKind::Term).await.map_err(|_|anyhow!("ack_failed"))?;
                        tracing::warn!(error_kind="invalid_observation","observation rejected; no domain changes committed");
                    },
                    _=> {
                        message.ack_with(AckKind::Nak(Some(Duration::from_secs(5)))).await.map_err(|_|anyhow!("ack_failed"))?;
                        tracing::warn!(error_kind="ingest_retry","observation not committed; retry scheduled");
                    }
                }
            }
        }
    }
}
fn permanent(e: &anyhow::Error) -> bool {
    match e.downcast_ref::<sqlx::Error>() {
        Some(sqlx::Error::Database(db)) => db
            .code()
            .is_some_and(|c| c.starts_with("23") || c.starts_with("22")),
        Some(_) => false,
        None => true,
    }
}
