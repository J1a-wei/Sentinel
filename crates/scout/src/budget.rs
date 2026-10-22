use anyhow::{Result, ensure};
use ed25519_dalek::SigningKey;
use sentinel_protocol::{Coverage, CoverageStatus, MAX_MESSAGE_BYTES, Observation, SignedEvent};

fn limited(event: &mut Observation, kind: &str) {
    event.coverage.insert(
        kind.into(),
        Coverage {
            status: CoverageStatus::Partial,
            reason: Some("limit_exceeded: inventory truncated to transport budget".into()),
        },
    );
}
/// Bound each category first, then use the actual signed-envelope size. Retain heartbeat fields.
pub fn sign_bounded(e: &mut Observation, key: &SigningKey) -> Result<Vec<u8>> {
    for kind in ["packages", "processes", "ports", "network"] {
        let trimmed = match kind {
            "packages" => {
                let t = e.packages.len() > 20_000;
                e.packages.truncate(20_000);
                t
            }
            "processes" => {
                let t = e.processes.len() > 8_000;
                e.processes.truncate(8_000);
                t
            }
            "ports" => {
                let t = e.ports.len() > 8_000;
                e.ports.truncate(8_000);
                t
            }
            _ => {
                let t = e.interfaces.len() > 256;
                e.interfaces.truncate(256);
                t
            }
        };
        if trimmed {
            limited(e, kind);
        }
    }
    e.validate()?;
    loop {
        // String encoding of the payload adds escaping bytes to the wire envelope.
        let payload = serde_json::to_string(e)?;
        let estimated=serde_json::to_vec(&serde_json::json!({"public_key":"0".repeat(64),"payload":payload,"signature":"0".repeat(128)}))?.len();
        if estimated <= MAX_MESSAGE_BYTES {
            return SignedEvent::sign(e, key);
        }
        let mut sizes = [
            ("packages", serde_json::to_vec(&e.packages)?.len()),
            ("processes", serde_json::to_vec(&e.processes)?.len()),
            ("ports", serde_json::to_vec(&e.ports)?.len()),
            ("network", serde_json::to_vec(&e.interfaces)?.len()),
        ];
        sizes.sort_by_key(|v| std::cmp::Reverse(v.1));
        let kind = sizes[0].0;
        ensure!(sizes[0].1 > 2, "base observation exceeds message limit");
        match kind {
            "packages" => e.packages.truncate(e.packages.len() / 2),
            "processes" => e.processes.truncate(e.processes.len() / 2),
            "ports" => e.ports.truncate(e.ports.len() / 2),
            _ => e.interfaces.truncate(e.interfaces.len() / 2),
        }
        limited(e, kind);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use sentinel_protocol::{Host, Metrics, Package, QueueHealth};
    use uuid::Uuid;
    pub fn fixture() -> Observation {
        Observation {
            queue_health: QueueHealth::default(),
            schema_version: 1,
            event_id: Uuid::new_v4(),
            asset_id: Uuid::new_v4(),
            installation_id: Uuid::new_v4(),
            instance_id: Uuid::new_v4(),
            active_epoch: 1,
            collection_sequence: 0,
            metric_sequence: 1,
            started_at: Utc::now(),
            observed_at: Utc::now(),
            scout_version: "fixture".into(),
            inventory_run_id: Uuid::new_v4(),
            packages_run_id: Uuid::new_v4(),
            ports_run_id: Uuid::new_v4(),
            host: Host {
                hostname: Some("fixture".into()),
                ..Host::default()
            },
            metrics: Metrics::default(),
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
            .map(|k| {
                (
                    k.into(),
                    Coverage {
                        status: CoverageStatus::Complete,
                        reason: None,
                    },
                )
            })
            .collect(),
        }
    }
    #[test]
    fn huge_packages_keep_heartbeat_and_mark_partial() -> Result<()> {
        let mut event = fixture();
        event.packages = (0..20_000)
            .map(|n| Package {
                name: format!("fixture-{n}-{}", "x".repeat(100)),
                version: "1:1.2.3-0ubuntu1".into(),
                architecture: "amd64".into(),
                source_name: None,
                source_version: None,
                origin: "unknown".into(),
            })
            .collect();
        let key = SigningKey::from_bytes(&[7; 32]);
        assert!(SignedEvent::sign(&event, &key).is_err());
        let bytes = sign_bounded(&mut event, &key)?;
        assert!(bytes.len() <= MAX_MESSAGE_BYTES);
        let (decoded, _, _) = SignedEvent::verify(&bytes)?;
        assert_eq!(decoded.host.hostname.as_deref(), Some("fixture"));
        assert!(!decoded.packages.is_empty());
        assert!(decoded.packages.len() < 20_000);
        assert_eq!(decoded.coverage["packages"].status, CoverageStatus::Partial);
        assert!(
            decoded.coverage["packages"]
                .reason
                .as_ref()
                .is_some_and(|s| s.contains("limit_exceeded"))
        );
        assert_eq!(decoded.coverage["host"].status, CoverageStatus::Complete);
        Ok(())
    }
    #[tokio::test]
    async fn identity_queue_survives_restart_locks_and_overflow() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let state = crate::state::LocalState::open(temp.path()).await?;
        let identity = state.identity.installation_id;
        let key = state.identity.key.verifying_key();
        assert!(crate::state::LocalState::open(temp.path()).await.is_err());
        let mut e = fixture();
        e.installation_id = identity;
        assert!(state.enqueue(e.clone()).await?);
        let before = state.next().await?.context("missing queued fixture")?;
        assert_eq!(state.health().await?.pending_events, 1);
        state.pool.close().await;
        drop(state);
        let state = crate::state::LocalState::open(temp.path()).await?;
        assert_eq!(state.identity.installation_id, identity);
        assert_eq!(state.identity.key.verifying_key(), key);
        let after = state.next().await?.context("missing persisted fixture")?;
        assert_eq!(before, after);
        // Fill only synthetic small spool records to exercise count protection quickly.
        let mut tx = state.pool.begin().await?;
        for n in 2..=crate::state::MAX_QUEUE_EVENTS {
            sqlx::query("INSERT INTO pending_events(id,sequence,subject,payload) VALUES($1,$2,'fixture',X'00')").bind(Uuid::new_v4().to_string()).bind(n).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        e.event_id = Uuid::new_v4();
        assert!(!state.enqueue(e).await?);
        let health = state.health().await?;
        assert_eq!(health.pending_events, crate::state::MAX_QUEUE_EVENTS);
        assert_eq!(health.overflow_count, 1);
        assert_eq!(
            state.next().await?.context("queue was overwritten")?,
            before
        );
        state.acknowledge(&before.0).await?;
        assert_eq!(
            state.health().await?.pending_events,
            crate::state::MAX_QUEUE_EVENTS - 1
        );
        state.pool.close().await;
        Ok(())
    }
    use anyhow::Context;
}
