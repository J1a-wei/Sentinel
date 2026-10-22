//! Bounded, signed observations shared by Hub and Scout. No remote execution messages.
use anyhow::{Context, Result, bail, ensure};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    net::IpAddr,
};
use uuid::Uuid;

pub const MAX_MESSAGE_BYTES: usize = 900_000;
pub const STREAM: &str = "SENTINEL_EVENTS";
pub const HANDLER: &str = "hub-inventory-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CoverageStatus {
    Complete,
    Partial,
    Unavailable,
    Unsupported,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Coverage {
    pub status: CoverageStatus,
    pub reason: Option<String>,
}
impl Coverage {
    pub fn complete(&self) -> bool {
        self.status == CoverageStatus::Complete
    }
    pub fn unknown(reason: &str) -> Self {
        Self {
            status: CoverageStatus::Unavailable,
            reason: Some(reason.into()),
        }
    }
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Host {
    pub fingerprint_sha256: Option<String>,
    pub hostname: Option<String>,
    pub os_id: Option<String>,
    pub os_version: Option<String>,
    pub kernel_version: Option<String>,
    pub architecture: Option<String>,
    pub cpu_model: Option<String>,
    pub logical_cpu_count: Option<i32>,
    pub boot_id: Option<Uuid>,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metrics {
    pub cpu_percent: Option<f64>,
    pub memory_total_bytes: Option<i64>,
    pub memory_available_bytes: Option<i64>,
    pub process_count: Option<i32>,
    pub running_process_count: Option<i32>,
    pub zombie_process_count: Option<i32>,
    pub load1: Option<f64>,
    pub swap_used_bytes: Option<i64>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Interface {
    pub ifindex: Option<u32>,
    pub kind: String,
    pub name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_bytes_per_second: Option<f64>,
    pub tx_bytes_per_second: Option<f64>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Process {
    pub pid: i32,
    pub start_ticks: i64,
    pub name: String,
    pub state: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Port {
    pub protocol: String,
    pub address: IpAddr,
    pub port: u16,
    pub network_namespace: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub architecture: String,
    pub source_name: Option<String>,
    pub source_version: Option<String>,
    pub origin: String,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueueHealth {
    pub pending_events: i64,
    pub pending_bytes: i64,
    pub overflow_count: i64,
    pub max_events: i64,
    pub max_bytes: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    #[serde(default)]
    pub queue_health: QueueHealth,
    pub schema_version: u32,
    pub event_id: Uuid,
    pub asset_id: Uuid,
    pub installation_id: Uuid,
    pub instance_id: Uuid,
    pub active_epoch: i64,
    pub collection_sequence: i64,
    pub metric_sequence: i64,
    pub observed_at: DateTime<Utc>,
    pub started_at: DateTime<Utc>,
    pub scout_version: String,
    pub inventory_run_id: Uuid,
    pub packages_run_id: Uuid,
    pub ports_run_id: Uuid,
    pub host: Host,
    pub metrics: Metrics,
    pub interfaces: Vec<Interface>,
    pub processes: Vec<Process>,
    pub ports: Vec<Port>,
    pub packages: Vec<Package>,
    pub coverage: BTreeMap<String, Coverage>,
}
impl Observation {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.schema_version == 1, "unsupported_schema");
        ensure!(
            self.active_epoch > 0
                && self.collection_sequence >= 0
                && self.collection_sequence < i64::MAX - 3
                && self.metric_sequence >= 0,
            "invalid_sequence"
        );
        ensure!(self.started_at <= self.observed_at, "invalid_time_range");
        for id in [
            self.event_id,
            self.asset_id,
            self.installation_id,
            self.instance_id,
            self.inventory_run_id,
            self.packages_run_id,
            self.ports_run_id,
        ] {
            ensure!(!id.is_nil(), "nil_id");
        }
        ensure!(
            self.inventory_run_id != self.packages_run_id
                && self.inventory_run_id != self.ports_run_id
                && self.ports_run_id != self.packages_run_id,
            "duplicate_run_id"
        );
        ensure!(
            self.packages.len() <= 20_000
                && self.processes.len() <= 8_000
                && self.ports.len() <= 8_000
                && self.interfaces.len() <= 256,
            "inventory_limit"
        );
        for key in [
            "host",
            "cpu",
            "memory",
            "network",
            "processes",
            "ports",
            "packages",
        ] {
            let c = self.coverage.get(key).context("missing_coverage")?;
            ensure!(
                c.complete() || c.reason.as_ref().is_some_and(|s| !s.is_empty()),
                "missing_coverage_reason"
            );
            if let Some(reason) = &c.reason {
                bounded(reason, 512)?;
            }
        }
        ensure!(self.coverage.len() <= 16, "coverage_limit");
        bounded(&self.scout_version, 64)?;
        for s in [
            &self.host.hostname,
            &self.host.os_id,
            &self.host.os_version,
            &self.host.kernel_version,
            &self.host.architecture,
            &self.host.cpu_model,
        ]
        .into_iter()
        .flatten()
        {
            bounded(s, 512)?;
        }
        if let Some(n) = self.host.logical_cpu_count {
            ensure!(n > 0, "invalid_cpu_count");
        }
        if let Some(f) = &self.host.fingerprint_sha256 {
            ensure!(
                f.len() == 64 && hex::decode(f).is_ok(),
                "invalid_fingerprint"
            );
        }
        let m = &self.metrics;
        if let Some(n) = m.cpu_percent {
            ensure!(n.is_finite() && (0.0..=100.0).contains(&n), "invalid_cpu");
        }
        for n in [
            m.memory_total_bytes,
            m.memory_available_bytes,
            m.swap_used_bytes,
        ]
        .into_iter()
        .flatten()
        {
            ensure!(n >= 0, "negative_metric");
        }
        for n in [
            m.process_count,
            m.running_process_count,
            m.zombie_process_count,
        ]
        .into_iter()
        .flatten()
        {
            ensure!(n >= 0, "negative_process_count");
        }
        if let (Some(total), Some(avail)) = (m.memory_total_bytes, m.memory_available_bytes) {
            ensure!(avail <= total, "invalid_memory");
        }
        if let Some(load) = m.load1 {
            ensure!(load.is_finite() && load >= 0.0, "invalid_load");
        }
        let mut seen = HashSet::new();
        for p in &self.packages {
            for v in [&p.name, &p.version, &p.architecture] {
                bounded(v, 256)?;
            }
            ensure!(seen.insert((&p.name, &p.architecture)), "duplicate_package");
            ensure!(
                matches!(p.origin.as_str(), "ubuntu" | "third_party" | "unknown"),
                "invalid_origin"
            );
            ensure!(
                p.source_name.is_some() == p.source_version.is_some(),
                "incomplete_source_package"
            );
            for s in [&p.source_name, &p.source_version].into_iter().flatten() {
                bounded(s, 256)?;
            }
        }
        let mut seen = HashSet::new();
        for p in &self.processes {
            ensure!(p.pid > 0 && p.start_ticks >= 0, "invalid_process");
            bounded(&p.name, 256)?;
            bounded(&p.state, 16)?;
            ensure!(seen.insert((p.pid, p.start_ticks)), "duplicate_process");
        }
        let mut seen = HashSet::new();
        for p in &self.ports {
            ensure!(
                matches!(p.protocol.as_str(), "tcp" | "udp") && p.port > 0,
                "invalid_port"
            );
            bounded(&p.network_namespace, 128)?;
            ensure!(
                seen.insert((&p.protocol, p.address, p.port, &p.network_namespace)),
                "duplicate_port"
            );
        }
        let mut seen = HashSet::new();
        for i in &self.interfaces {
            bounded(&i.kind, 32)?;
            bounded(&i.name, 128)?;
            ensure!(seen.insert(&i.name), "duplicate_interface");
            for n in [i.rx_bytes_per_second, i.tx_bytes_per_second]
                .into_iter()
                .flatten()
            {
                ensure!(n.is_finite() && n >= 0.0, "invalid_rate");
            }
        }
        Ok(())
    }
    pub fn subject(&self) -> String {
        format!("sentinel.events.{}", self.installation_id)
    }
    pub fn complete(&self, keys: &[&str]) -> bool {
        keys.iter()
            .all(|k| self.coverage.get(*k).is_some_and(Coverage::complete))
    }
}
pub fn bounded(s: &str, max: usize) -> Result<()> {
    ensure!(
        !s.is_empty() && s.len() <= max && !s.chars().any(char::is_control),
        "invalid_text"
    );
    Ok(())
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedEvent {
    pub public_key: String,
    pub payload: String,
    pub signature: String,
}
impl SignedEvent {
    pub fn sign(event: &Observation, key: &SigningKey) -> Result<Vec<u8>> {
        event.validate()?;
        let payload = serde_json::to_string(event)?;
        let message = Self {
            public_key: hex::encode(key.verifying_key().to_bytes()),
            signature: hex::encode(key.sign(payload.as_bytes()).to_bytes()),
            payload,
        };
        let bytes = serde_json::to_vec(&message)?;
        ensure!(bytes.len() <= MAX_MESSAGE_BYTES, "message_too_large");
        Ok(bytes)
    }
    pub fn verify(bytes: &[u8]) -> Result<(Observation, [u8; 32], [u8; 32])> {
        ensure!(bytes.len() <= MAX_MESSAGE_BYTES, "message_too_large");
        let signed: Self = serde_json::from_slice(bytes).context("invalid_envelope")?;
        let key = decode_key(&signed.public_key)?;
        let signature =
            Signature::from_slice(&hex::decode(&signed.signature).context("invalid_signature")?)
                .context("invalid_signature")?;
        key.verify_strict(signed.payload.as_bytes(), &signature)
            .context("invalid_signature")?;
        let event: Observation =
            serde_json::from_str(&signed.payload).context("invalid_payload")?;
        event.validate()?;
        Ok((
            event,
            hash(&key.to_bytes()),
            hash(signed.payload.as_bytes()),
        ))
    }
}
pub fn decode_key(key: &str) -> Result<VerifyingKey> {
    let bytes: [u8; 32] = hex::decode(key)
        .context("invalid_public_key")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid_public_key"))?;
    let key = VerifyingKey::from_bytes(&bytes).context("invalid_public_key")?;
    ensure!(!key.is_weak(), "weak_public_key");
    Ok(key)
}
pub fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Secrets never implement Debug and must never be written to logs.
pub fn secret(name: &str) -> Result<Option<String>> {
    let direct = std::env::var(name).ok();
    let file = std::env::var(format!("{name}_FILE")).ok();
    match (direct, file) {
        (Some(_), Some(_)) => bail!("{name} and {name}_FILE are mutually exclusive"),
        (Some(v), None) => {
            ensure!(!v.trim().is_empty(), "{name} must not be empty");
            Ok(Some(v))
        }
        (None, Some(path)) => {
            let bytes = std::fs::read(path).with_context(|| format!("read {name}_FILE"))?;
            ensure!(bytes.len() <= 16_384, "secret file too large");
            let v = String::from_utf8(bytes)
                .context("secret is not UTF-8")?
                .trim_end_matches(['\r', '\n'])
                .to_owned();
            ensure!(!v.trim().is_empty(), "{name}_FILE must not be empty");
            Ok(Some(v))
        }
        (None, None) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_invalid_envelope_key_and_limits() {
        assert!(
            SignedEvent::verify(br#"{"public_key":"00","payload":"{}","signature":"00"}"#).is_err()
        );
        assert!(SignedEvent::verify(&vec![b' '; MAX_MESSAGE_BYTES + 1]).is_err());
        assert!(decode_key(&"00".repeat(32)).is_err());
        assert!(bounded("line\nsecret", 64).is_err());
    }
}
