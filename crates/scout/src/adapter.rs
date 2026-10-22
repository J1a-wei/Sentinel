use crate::collectors::{self, CollectionBatch};
use anyhow::Result;
use chrono::Utc;
use sentinel_protocol::{
    Coverage, CoverageStatus, Host, Interface, Metrics, Observation, Package, Port, Process,
    QueueHealth,
};
use std::{
    collections::{BTreeMap, HashSet},
    time::Instant,
};
use uuid::Uuid;

pub struct Sample {
    pub at: Instant,
    pub boot: Option<Uuid>,
    pub cpu: Option<(u64, u64)>,
    pub network: BTreeMap<(u32, String), (u64, u64)>,
}
fn network_rate(
    previous: Option<&Sample>,
    current: &Sample,
    index: Option<u32>,
    name: &str,
) -> Option<(f64, f64)> {
    let prev = previous?;
    if current.boot.is_none() || current.boot != prev.boot || current.at <= prev.at {
        return None;
    }
    let key = (index?, name.to_owned());
    let (rx, tx) = current.network.get(&key)?;
    let (old_rx, old_tx) = prev.network.get(&key)?;
    let seconds = current.at.duration_since(prev.at).as_secs_f64();
    Some((
        rx.checked_sub(*old_rx)? as f64 / seconds,
        tx.checked_sub(*old_tx)? as f64 / seconds,
    ))
}
fn coverage(c: &collectors::Coverage) -> Coverage {
    let status = match c.status {
        collectors::CoverageStatus::Complete => CoverageStatus::Complete,
        collectors::CoverageStatus::Partial => CoverageStatus::Partial,
        collectors::CoverageStatus::NotApplicable => CoverageStatus::Unsupported,
        _ => CoverageStatus::Unavailable,
    };
    // The DTO's raw parse errors may contain input text. Only a bounded status reason crosses the wire.
    let reason = if status == CoverageStatus::Complete {
        None
    } else {
        Some(
            match c.status {
                collectors::CoverageStatus::Partial => "partial_source_coverage",
                collectors::CoverageStatus::Missing => "source_missing",
                collectors::CoverageStatus::Error => "source_read_or_parse_error",
                _ => "source_not_applicable",
            }
            .into(),
        )
    };
    let reason = if status != CoverageStatus::Complete {
        let detail = c.reason.as_deref().unwrap_or("").to_lowercase();
        if detail.contains("permission denied") {
            Some("source_permission_denied".into())
        } else if detail.contains("truncat") || detail.contains("exceeds size") {
            Some("limit_exceeded: collection source budget".into())
        } else if detail.contains("ifindex") {
            Some("interface_identity_missing".into())
        } else {
            reason
        }
    } else {
        reason
    };
    Coverage { status, reason }
}
fn i64_value(v: Option<u64>) -> Option<i64> {
    v.and_then(|n| n.try_into().ok())
}
fn cpu_counters(cpu: &collectors::CpuTimes) -> Option<(u64, u64)> {
    // guest and guest_nice are already included in user/nice; never count them twice.
    let mut total = 0u64;
    for n in [
        cpu.user?,
        cpu.nice?,
        cpu.system?,
        cpu.idle?,
        cpu.iowait.unwrap_or(0),
        cpu.irq.unwrap_or(0),
        cpu.softirq.unwrap_or(0),
        cpu.steal.unwrap_or(0),
    ] {
        total = total.checked_add(n)?;
    }
    Some((total, cpu.idle?.checked_add(cpu.iowait.unwrap_or(0))?))
}
pub fn cpu_rate(previous: Option<&Sample>, current: &Sample) -> Option<f64> {
    let prev = previous?;
    if current.boot.is_none() || current.boot != prev.boot || current.at <= prev.at {
        return None;
    }
    let (total, idle) = current.cpu?;
    let (pt, pi) = prev.cpu?;
    let delta = total.checked_sub(pt)?;
    let idle = idle.checked_sub(pi)?;
    if delta == 0 || idle > delta {
        return None;
    }
    Some(100.0 * (delta - idle) as f64 / delta as f64)
}
pub fn convert(
    batch: CollectionBatch,
    previous: Option<&Sample>,
    at: Instant,
) -> Result<(Observation, Sample)> {
    let mut map: BTreeMap<String, Coverage> = [
        ("host", coverage(&batch.host.coverage)),
        ("cpu", coverage(&batch.metrics.cpu_coverage)),
        ("memory", coverage(&batch.metrics.memory_coverage)),
        ("network", coverage(&batch.metrics.network_coverage)),
        ("ports", coverage(&batch.ports.coverage)),
        ("processes", coverage(&batch.processes.coverage)),
        ("packages", coverage(&batch.packages.coverage)),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v))
    .collect();
    let h = batch.host.info.unwrap_or_default();
    // A collector binary can run under emulation or inspect a different mounted root.
    // Its build target is not evidence of the observed host architecture.
    let architecture = if h.architecture_source.as_deref() == Some("dpkg_arch") {
        h.architecture
    } else {
        map.insert(
            "architecture".into(),
            Coverage::unknown("host_architecture_not_observed"),
        );
        if map.get("host").is_some_and(Coverage::complete) {
            map.insert(
                "host".into(),
                Coverage {
                    status: CoverageStatus::Partial,
                    reason: Some("host_architecture_not_observed".into()),
                },
            );
        }
        None
    };
    let host = Host {
        fingerprint_sha256: h.fingerprint_sha256,
        hostname: h.hostname,
        os_id: h.os_id,
        os_version: h.os_version,
        kernel_version: h.kernel_version,
        architecture,
        cpu_model: h.cpu_model,
        logical_cpu_count: h.logical_cpu_count.and_then(|n| n.try_into().ok()),
        boot_id: h.boot_id.as_deref().and_then(|v| v.parse().ok()),
    };
    let network = batch.metrics.network.unwrap_or_default().interfaces;
    let sample = Sample {
        at,
        boot: host.boot_id,
        cpu: batch
            .metrics
            .cpu
            .as_ref()
            .and_then(|v| v.total.as_ref())
            .and_then(cpu_counters),
        network: network
            .iter()
            .filter_map(|i| {
                i.ifindex
                    .map(|index| ((index, i.name.clone()), (i.rx_bytes, i.tx_bytes)))
            })
            .collect(),
    };
    let cpu = cpu_rate(previous, &sample);
    if cpu.is_none() {
        map.insert(
            "cpu".into(),
            Coverage::unknown("first_sample_reset_or_missing_boot_identity"),
        );
    }
    if host.fingerprint_sha256.is_none() {
        map.insert(
            "fingerprint".into(),
            Coverage::unknown("machine_id_missing_or_invalid"),
        );
    }
    let memory = batch.metrics.memory.unwrap_or_default();
    let mut metrics = Metrics {
        cpu_percent: cpu,
        memory_total_bytes: i64_value(memory.mem_total_bytes),
        memory_available_bytes: i64_value(memory.mem_available_bytes),
        swap_used_bytes: i64_value(
            memory
                .swap_total_bytes
                .zip(memory.swap_free_bytes)
                .and_then(|(t, f)| t.checked_sub(f)),
        ),
        ..Metrics::default()
    };
    let interfaces: Vec<Interface> = network
        .into_iter()
        .map(|i| {
            let rates = network_rate(previous, &sample, i.ifindex, &i.name);
            Interface {
                ifindex: i.ifindex,
                kind: format!("{:?}", i.kind).to_lowercase(),
                name: i.name,
                rx_bytes: i.rx_bytes,
                tx_bytes: i.tx_bytes,
                rx_bytes_per_second: rates.map(|r| r.0),
                tx_bytes_per_second: rates.map(|r| r.1),
            }
        })
        .collect();
    let known = interfaces
        .iter()
        .filter(|i| i.rx_bytes_per_second.is_some())
        .count();
    map.insert(
        "network_rates".into(),
        if known == interfaces.len() && !interfaces.is_empty() {
            Coverage {
                status: CoverageStatus::Complete,
                reason: None,
            }
        } else {
            Coverage {
                status: if known > 0 {
                    CoverageStatus::Partial
                } else {
                    CoverageStatus::Unavailable
                },
                reason: Some("first_sample_counter_reset_or_interface_identity_changed".into()),
            }
        },
    );
    let mut seen = HashSet::new();
    let ports = batch
        .ports
        .endpoints
        .into_iter()
        .filter_map(|p| {
            let address = p.address.parse().ok()?;
            let protocol = match p.protocol {
                collectors::PortProtocol::Tcp => "tcp",
                collectors::PortProtocol::Udp => "udp",
            };
            if p.port == 0 || !seen.insert((protocol, address, p.port)) {
                return None;
            }
            Some(Port {
                protocol: protocol.into(),
                address,
                port: p.port,
                network_namespace: "host:proc/1/net".into(),
            })
        })
        .collect();
    let mut seen = HashSet::new();
    let packages = batch
        .packages
        .entries
        .into_iter()
        .filter_map(|p| {
            if !seen.insert((p.name.clone(), p.architecture.clone())) {
                return None;
            }
            let source = if p.source_name.is_some() && p.source_version.is_some() {
                (p.source_name, p.source_version)
            } else {
                (None, None)
            };
            Some(Package {
                name: p.name,
                version: p.version,
                architecture: p.architecture,
                source_name: source.0,
                source_version: source.1,
                origin: match p.origin_status {
                    collectors::OriginStatus::Ubuntu => "ubuntu",
                    collectors::OriginStatus::ThirdParty => "third_party",
                    collectors::OriginStatus::Unknown => "unknown",
                }
                .into(),
            })
        })
        .collect();
    let processes = processes(&batch.processes, &mut metrics);
    let now = Utc::now();
    Ok((
        Observation {
            queue_health: QueueHealth::default(),
            schema_version: 1,
            event_id: Uuid::new_v4(),
            asset_id: Uuid::nil(),
            installation_id: Uuid::nil(),
            instance_id: Uuid::nil(),
            active_epoch: 1,
            collection_sequence: 0,
            metric_sequence: 0,
            started_at: now,
            observed_at: now,
            scout_version: env!("CARGO_PKG_VERSION").into(),
            inventory_run_id: Uuid::new_v4(),
            packages_run_id: Uuid::new_v4(),
            ports_run_id: Uuid::new_v4(),
            host,
            metrics,
            interfaces,
            processes,
            ports,
            packages,
            coverage: map,
        },
        sample,
    ))
}
fn processes(section: &collectors::ProcessSection, metrics: &mut Metrics) -> Vec<Process> {
    if section.coverage.is_usable() {
        metrics.process_count = i32::try_from(section.total_count).ok();
        metrics.running_process_count = i32::try_from(section.running_count).ok();
        metrics.zombie_process_count = i32::try_from(section.zombie_count).ok();
    }
    section
        .entries
        .iter()
        .map(|p| Process {
            pid: p.pid,
            start_ticks: p.start_ticks,
            name: p.name.clone(),
            state: p.state_code.clone(),
        })
        .collect()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cpu_first_sample_reset_and_reboot_are_unknown() {
        let boot = Uuid::new_v4();
        let at = Instant::now();
        let first = Sample {
            at,
            boot: Some(boot),
            cpu: Some((1000, 850)),
            network: BTreeMap::new(),
        };
        assert_eq!(cpu_rate(None, &first), None);
        let second = Sample {
            at: at + std::time::Duration::from_secs(1),
            boot: Some(boot),
            cpu: Some((1100, 940)),
            network: BTreeMap::new(),
        };
        assert_eq!(cpu_rate(Some(&first), &second), Some(10.0));
        let reset = Sample {
            at: second.at,
            boot: Some(boot),
            cpu: Some((1, 0)),
            network: BTreeMap::new(),
        };
        assert_eq!(cpu_rate(Some(&first), &reset), None);
        let reboot = Sample {
            at: second.at,
            boot: Some(Uuid::new_v4()),
            cpu: second.cpu,
            network: BTreeMap::new(),
        };
        assert_eq!(cpu_rate(Some(&first), &reboot), None);
    }
    #[test]
    fn network_rates_use_monotonic_time_and_identity() {
        let boot = Uuid::new_v4();
        let at = Instant::now();
        let first = Sample {
            at,
            boot: Some(boot),
            cpu: None,
            network: [((2, "eth0".into()), (1000, 2000))].into(),
        };
        let mut second = Sample {
            at: at + std::time::Duration::from_millis(2500),
            boot: Some(boot),
            cpu: None,
            network: [((2, "eth0".into()), (1500, 3000))].into(),
        };
        assert_eq!(network_rate(None, &first, Some(2), "eth0"), None);
        assert_eq!(
            network_rate(Some(&first), &second, Some(2), "eth0"),
            Some((200.0, 400.0))
        );
        assert_eq!(network_rate(Some(&first), &second, Some(3), "eth0"), None);
        assert_eq!(network_rate(Some(&first), &second, None, "eth0"), None);
        second.network.insert((2, "eth0".into()), (10, 20));
        assert_eq!(network_rate(Some(&first), &second, Some(2), "eth0"), None);
        second.boot = Some(Uuid::new_v4());
        assert_eq!(network_rate(Some(&first), &second, Some(2), "eth0"), None);
    }
    #[test]
    fn guest_time_is_not_double_counted() {
        let counters = collectors::CpuTimes {
            user: Some(20),
            nice: Some(5),
            system: Some(10),
            idle: Some(65),
            guest: Some(10),
            guest_nice: Some(2),
            ..Default::default()
        };
        assert_eq!(cpu_counters(&counters), Some((100, 65)));
    }
}
