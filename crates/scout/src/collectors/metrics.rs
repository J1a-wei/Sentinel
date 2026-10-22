//! Raw host counters from `/proc`: CPU time jiffies, memory, and per-interface
//! network counters. No rates are computed here; the caller derives rates from
//! adjacent samples and treats the first sample or a counter reset as unknown.

use serde::{Deserialize, Serialize};

use super::CollectOptions;
use super::coverage::{Coverage, CoverageBuilder};
use super::safe_io::{HostFs, ReadError};

/// Raw per-CPU jiffy counters from `/proc/stat`. `None` means the field was
/// absent or unparseable, never zero.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CpuTimes {
    pub user: Option<u64>,
    pub nice: Option<u64>,
    pub system: Option<u64>,
    pub idle: Option<u64>,
    pub iowait: Option<u64>,
    pub irq: Option<u64>,
    pub softirq: Option<u64>,
    pub steal: Option<u64>,
    pub guest: Option<u64>,
    pub guest_nice: Option<u64>,
}

impl CpuTimes {
    /// Sum of the counters that are present. Returns `None` if the core fields
    /// (`user`, `nice`, `system`, `idle`) are not all present, or if the sum
    /// overflows `u64`.
    ///
    /// `guest` and `guest_nice` are intentionally excluded: Linux already
    /// accounts guest time inside `user` and `nice`, so adding them again would
    /// double-count.
    pub fn total_jiffies(&self) -> Option<u64> {
        let mut total = self.user?;
        for value in [
            self.nice?,
            self.system?,
            self.idle?,
            self.iowait.unwrap_or(0),
            self.irq.unwrap_or(0),
            self.softirq.unwrap_or(0),
            self.steal.unwrap_or(0),
        ] {
            total = total.checked_add(value)?;
        }
        Some(total)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PerCpuTimes {
    pub index: u32,
    pub times: CpuTimes,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CpuStat {
    pub total: Option<CpuTimes>,
    pub per_cpu: Vec<PerCpuTimes>,
    pub btime_unix_seconds: Option<i64>,
    pub parse_errors: Vec<String>,
}

/// Memory values from `/proc/meminfo`, converted from kB to bytes where the
/// kernel reports a `kB` unit. Unit-less fields (for example `HugePages_Total`)
/// keep their raw value.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Meminfo {
    pub mem_total_bytes: Option<u64>,
    pub mem_free_bytes: Option<u64>,
    pub mem_available_bytes: Option<u64>,
    pub buffers_bytes: Option<u64>,
    pub cached_bytes: Option<u64>,
    pub swap_cached_bytes: Option<u64>,
    pub active_bytes: Option<u64>,
    pub inactive_bytes: Option<u64>,
    pub dirty_bytes: Option<u64>,
    pub writeback_bytes: Option<u64>,
    pub shmem_bytes: Option<u64>,
    pub slab_bytes: Option<u64>,
    pub sreclaimable_bytes: Option<u64>,
    pub sunreclaim_bytes: Option<u64>,
    pub swap_total_bytes: Option<u64>,
    pub swap_free_bytes: Option<u64>,
    pub huge_pages_total: Option<u64>,
    pub huge_pages_free: Option<u64>,
    pub parse_errors: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterfaceKind {
    Physical,
    Bridge,
    Virtual,
    Loopback,
    #[default]
    Unknown,
}

/// Raw per-interface counters from `/proc/net/dev`. All values are cumulative
/// since the interface instance started; resets are the caller's concern.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NetInterfaceCounters {
    pub name: String,
    pub kind: InterfaceKind,
    /// Interface index from `sys/class/net/<name>/ifindex`. `None` when the
    /// optional `/sys` mount is absent or the file could not be read.
    pub ifindex: Option<u32>,
    pub rx_bytes: u64,
    pub rx_packets: u64,
    pub rx_errors: u64,
    pub rx_dropped: u64,
    pub rx_fifo: u64,
    pub rx_frame: u64,
    pub rx_compressed: u64,
    pub rx_multicast: u64,
    pub tx_bytes: u64,
    pub tx_packets: u64,
    pub tx_errors: u64,
    pub tx_dropped: u64,
    pub tx_fifo: u64,
    pub tx_collisions: u64,
    pub tx_carrier: u64,
    pub tx_compressed: u64,
}

impl Default for NetInterfaceCounters {
    fn default() -> Self {
        NetInterfaceCounters {
            name: String::new(),
            kind: InterfaceKind::Unknown,
            ifindex: None,
            rx_bytes: 0,
            rx_packets: 0,
            rx_errors: 0,
            rx_dropped: 0,
            rx_fifo: 0,
            rx_frame: 0,
            rx_compressed: 0,
            rx_multicast: 0,
            tx_bytes: 0,
            tx_packets: 0,
            tx_errors: 0,
            tx_dropped: 0,
            tx_fifo: 0,
            tx_collisions: 0,
            tx_carrier: 0,
            tx_compressed: 0,
        }
    }
}

/// Which network namespace the counters describe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkView {
    /// `/proc/net` (the `self/net` view of the procfs mount).
    ProcNetSelf,
    /// `/proc/<pid>/net` for an explicit process.
    PidNamespace,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NetCounters {
    pub interfaces: Vec<NetInterfaceCounters>,
    pub parse_errors: Vec<String>,
    pub source_prefix: String,
    pub view: NetworkView,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct MetricsSection {
    pub coverage: Coverage,
    pub cpu_coverage: Coverage,
    pub memory_coverage: Coverage,
    pub network_coverage: Coverage,
    pub cpu: Option<CpuStat>,
    pub memory: Option<Meminfo>,
    pub network: Option<NetCounters>,
}

impl MetricsSection {
    pub fn skipped() -> Self {
        MetricsSection {
            coverage: Coverage::not_applicable("metrics collector disabled"),
            cpu_coverage: Coverage::not_applicable("disabled"),
            memory_coverage: Coverage::not_applicable("disabled"),
            network_coverage: Coverage::not_applicable("disabled"),
            ..MetricsSection::default()
        }
    }
}

fn parse_cpu_times(fields: &[&str]) -> (CpuTimes, u32) {
    let get = |index: usize| {
        fields
            .get(index)
            .and_then(|value| value.parse::<u64>().ok())
    };
    let times = CpuTimes {
        user: get(0),
        nice: get(1),
        system: get(2),
        idle: get(3),
        iowait: get(4),
        irq: get(5),
        softirq: get(6),
        steal: get(7),
        guest: get(8),
        guest_nice: get(9),
    };
    let missing_core = [times.user, times.nice, times.system, times.idle]
        .iter()
        .filter(|value| value.is_none())
        .count() as u32;
    (times, missing_core)
}

/// Parse `/proc/stat`.
pub fn parse_proc_stat(input: &str) -> CpuStat {
    let mut stat = CpuStat::default();
    for raw in input.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(first) = parts.next() else {
            continue;
        };

        if first == "btime" {
            match parts.next().and_then(|value| value.parse::<i64>().ok()) {
                Some(value) if value > 0 => stat.btime_unix_seconds = Some(value),
                _ => stat.parse_errors.push("btime: invalid value".to_string()),
            }
            continue;
        }

        let Some(rest) = first.strip_prefix("cpu") else {
            continue;
        };
        let fields: Vec<&str> = parts.collect();
        let (times, missing_core) = parse_cpu_times(&fields);
        if rest.is_empty() {
            if missing_core > 0 {
                stat.parse_errors
                    .push(format!("cpu: {missing_core} core fields unparseable"));
            }
            stat.total = Some(times);
        } else {
            match rest.parse::<u32>() {
                Ok(index) => {
                    if missing_core > 0 {
                        stat.parse_errors.push(format!(
                            "cpu{index}: {missing_core} core fields unparseable"
                        ));
                    }
                    stat.per_cpu.push(PerCpuTimes { index, times });
                }
                Err(_) => stat
                    .parse_errors
                    .push(format!("{first}: invalid cpu index")),
            }
        }
    }
    stat.per_cpu.sort_by_key(|entry| entry.index);
    stat
}

/// Parse `/proc/meminfo`.
pub fn parse_meminfo(input: &str) -> Meminfo {
    let mut info = Meminfo::default();
    for raw in input.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        // Parse errors reach `coverage.reason`; never echo the raw line (or
        // any source text) into them.
        let Some((key, rest)) = line.split_once(':') else {
            info.parse_errors
                .push("malformed line without ':'".to_string());
            continue;
        };
        let key = key.trim();
        let mut fields = rest.split_whitespace();
        let Some(raw_value) = fields.next() else {
            info.parse_errors.push(format!("{key}: missing value"));
            continue;
        };
        let Ok(value) = raw_value.parse::<u64>() else {
            info.parse_errors.push(format!("{key}: non-numeric value"));
            continue;
        };
        let bytes = match fields.next() {
            Some("kB") => Some(value.saturating_mul(1024)),
            Some(_) => Some(value),
            None => Some(value),
        };

        match key {
            "MemTotal" => info.mem_total_bytes = bytes,
            "MemFree" => info.mem_free_bytes = bytes,
            "MemAvailable" => info.mem_available_bytes = bytes,
            "Buffers" => info.buffers_bytes = bytes,
            "Cached" => info.cached_bytes = bytes,
            "SwapCached" => info.swap_cached_bytes = bytes,
            "Active" => info.active_bytes = bytes,
            "Inactive" => info.inactive_bytes = bytes,
            "Dirty" => info.dirty_bytes = bytes,
            "Writeback" => info.writeback_bytes = bytes,
            "Shmem" => info.shmem_bytes = bytes,
            "Slab" => info.slab_bytes = bytes,
            "SReclaimable" => info.sreclaimable_bytes = bytes,
            "SUnreclaim" => info.sunreclaim_bytes = bytes,
            "SwapTotal" => info.swap_total_bytes = bytes,
            "SwapFree" => info.swap_free_bytes = bytes,
            "HugePages_Total" => info.huge_pages_total = bytes,
            "HugePages_Free" => info.huge_pages_free = bytes,
            _ => {}
        }
    }
    info
}

/// Parse `/proc/net/dev`.
pub fn parse_net_dev(input: &str) -> NetCounters {
    let mut out = NetCounters::default();
    for raw in input.lines() {
        // Interface names never contain ':' except Ethernet aliases, which
        // still end with the delimiter colon, so the last ':' is the separator.
        let Some(colon) = raw.rfind(':') else {
            continue;
        };
        let name = raw[..colon].trim();
        if name.is_empty() {
            continue;
        }
        let rest = &raw[colon + 1..];
        let fields: Vec<&str> = rest.split_whitespace().collect();
        if fields.len() < 16 {
            out.parse_errors.push(format!(
                "interface '{name}': {} fields, expected 16",
                fields.len()
            ));
            continue;
        }
        let mut numbers = Vec::with_capacity(16);
        let mut valid = true;
        for value in fields.iter().take(16) {
            match value.parse::<u64>() {
                Ok(number) => numbers.push(number),
                Err(_) => {
                    valid = false;
                    break;
                }
            }
        }
        if !valid {
            out.parse_errors
                .push(format!("interface '{name}': non-numeric counter"));
            continue;
        }
        out.interfaces.push(NetInterfaceCounters {
            name: name.to_string(),
            kind: InterfaceKind::Unknown,
            ifindex: None,
            rx_bytes: numbers[0],
            rx_packets: numbers[1],
            rx_errors: numbers[2],
            rx_dropped: numbers[3],
            rx_fifo: numbers[4],
            rx_frame: numbers[5],
            rx_compressed: numbers[6],
            rx_multicast: numbers[7],
            tx_bytes: numbers[8],
            tx_packets: numbers[9],
            tx_errors: numbers[10],
            tx_dropped: numbers[11],
            tx_fifo: numbers[12],
            tx_collisions: numbers[13],
            tx_carrier: numbers[14],
            tx_compressed: numbers[15],
        });
    }
    out
}

/// Best-effort interface classification using `sys/class/net`. `Unknown` when
/// `/sys` is not mounted.
fn classify_interface(fs: &HostFs, name: &str) -> InterfaceKind {
    if name == "lo" {
        return InterfaceKind::Loopback;
    }
    if fs.entry_exists(&format!("sys/class/net/{name}/bridge")) {
        return InterfaceKind::Bridge;
    }
    if fs.entry_exists(&format!("sys/class/net/{name}/device")) {
        return InterfaceKind::Physical;
    }
    if fs.entry_exists(&format!("sys/class/net/{name}")) {
        return InterfaceKind::Virtual;
    }
    InterfaceKind::Unknown
}

/// Read `sys/class/net/<name>/ifindex`. A missing file is `None`, not an error:
/// `/sys` is an optional mount and the caller records the coverage reason.
fn read_ifindex(fs: &HostFs, name: &str, max_bytes: u64) -> Result<Option<u32>, ReadError> {
    let path = format!("sys/class/net/{name}/ifindex");
    match fs.read_to_string(&path, Some(max_bytes)) {
        Ok(text) => Ok(text.trim().parse::<u32>().ok()),
        Err(err) if err.is_not_found() => Ok(None),
        Err(err) => Err(err),
    }
}

fn network_view(prefix: &str) -> NetworkView {
    if prefix == "proc/net" {
        return NetworkView::ProcNetSelf;
    }
    if let Some(rest) = prefix.strip_prefix("proc/")
        && let Some(pid) = rest.strip_suffix("/net")
        && !pid.is_empty()
        && pid.chars().all(|ch| ch.is_ascii_digit())
    {
        return NetworkView::PidNamespace;
    }
    NetworkView::Unknown
}

/// Read CPU, memory and network counters once.
pub fn collect(fs: &HostFs, options: &CollectOptions) -> MetricsSection {
    let cpu = collect_cpu(fs, options);
    let memory = collect_memory(fs, options);
    let network = collect_network(fs, options);

    let coverage = Coverage::aggregate([
        &cpu.cpu_coverage,
        &memory.memory_coverage,
        &network.network_coverage,
    ]);

    MetricsSection {
        coverage,
        cpu_coverage: cpu.cpu_coverage,
        memory_coverage: memory.memory_coverage,
        network_coverage: network.network_coverage,
        cpu: cpu.cpu,
        memory: memory.memory,
        network: network.network,
    }
}

fn collect_cpu(fs: &HostFs, options: &CollectOptions) -> MetricsSection {
    let mut builder = CoverageBuilder::new();
    builder.source("proc/stat");
    let mut section = MetricsSection::default();
    match fs.read_to_string("proc/stat", Some(options.max_file_bytes)) {
        Ok(text) => {
            let parsed = parse_proc_stat(&text);
            for error in &parsed.parse_errors {
                builder.error(format!("proc/stat: {error}"));
            }
            builder.success();
            section.cpu = Some(parsed);
        }
        Err(err) if err.is_not_found() => builder.missing(err.as_reason("proc/stat")),
        Err(err) => builder.error(err.as_reason("proc/stat")),
    }
    section.cpu_coverage = builder.finish();
    section
}

fn collect_memory(fs: &HostFs, options: &CollectOptions) -> MetricsSection {
    let mut builder = CoverageBuilder::new();
    builder.source("proc/meminfo");
    let mut section = MetricsSection::default();
    match fs.read_to_string("proc/meminfo", Some(options.max_file_bytes)) {
        Ok(text) => {
            let parsed = parse_meminfo(&text);
            for error in &parsed.parse_errors {
                builder.error(format!("proc/meminfo: {error}"));
            }
            builder.success();
            section.memory = Some(parsed);
        }
        Err(err) if err.is_not_found() => builder.missing(err.as_reason("proc/meminfo")),
        Err(err) => builder.error(err.as_reason("proc/meminfo")),
    }
    section.memory_coverage = builder.finish();
    section
}

fn collect_network(fs: &HostFs, options: &CollectOptions) -> MetricsSection {
    let prefix = options.network_proc_prefix.trim_end_matches('/');
    let source = format!("{prefix}/dev");
    let mut builder = CoverageBuilder::new();
    builder.source(&source);
    builder.source("sys/class/net");
    let mut section = MetricsSection::default();
    match fs.read_to_string(&source, Some(options.max_file_bytes)) {
        Ok(text) => {
            let mut parsed = parse_net_dev(&text);
            for error in &parsed.parse_errors {
                builder.error(format!("{source}: {error}"));
            }
            let mut missing_ifindex = 0u64;
            for interface in &mut parsed.interfaces {
                interface.kind = classify_interface(fs, &interface.name);
                let path = format!("sys/class/net/{}/ifindex", interface.name);
                match read_ifindex(fs, &interface.name, options.max_file_bytes) {
                    Ok(Some(index)) => interface.ifindex = Some(index),
                    Ok(None) => missing_ifindex += 1,
                    Err(err) => {
                        builder.error(err.as_reason(&path));
                        missing_ifindex += 1;
                    }
                }
            }
            parsed.source_prefix = prefix.to_string();
            parsed.view = network_view(prefix);
            builder.success();
            if missing_ifindex > 0 {
                builder.partial(format!(
                    "sys/class/net: ifindex unavailable for {missing_ifindex} interface(s)"
                ));
            }
            section.network = Some(parsed);
        }
        Err(err) if err.is_not_found() => builder.missing(err.as_reason(&source)),
        Err(err) => builder.error(err.as_reason(&source)),
    }
    section.network_coverage = builder.finish();
    section
}

#[cfg(test)]
mod tests {
    use super::super::coverage::CoverageStatus;
    use super::*;

    // Fictional /proc/stat fixture.
    const PROC_STAT: &str = "\
cpu  100 20 30 4000 50 0 10 5 0 0
cpu0 50 10 15 2000 25 0 5 2 0 0
cpu1 50 10 15 2000 25 0 5 3 0 0
intr 12345 0 0
btime 1700000000
ctxt 999
processes 42
";

    #[test]
    fn proc_stat_parses_total_and_per_cpu() {
        let stat = parse_proc_stat(PROC_STAT);
        let total = stat.total.expect("total cpu line");
        assert_eq!(total.user, Some(100));
        assert_eq!(total.nice, Some(20));
        assert_eq!(total.system, Some(30));
        assert_eq!(total.idle, Some(4000));
        assert_eq!(total.iowait, Some(50));
        assert_eq!(total.steal, Some(5));
        assert_eq!(
            total.total_jiffies(),
            Some(100 + 20 + 30 + 4000 + 50 + 10 + 5)
        );
        assert_eq!(stat.per_cpu.len(), 2);
        assert_eq!(stat.per_cpu[0].index, 0);
        assert_eq!(stat.per_cpu[1].index, 1);
        assert_eq!(stat.btime_unix_seconds, Some(1_700_000_000));
        assert!(stat.parse_errors.is_empty());
    }

    #[test]
    fn proc_stat_missing_total_is_none() {
        let stat = parse_proc_stat("cpu0 1 2 3 4\nbtime 1700000000\n");
        assert_eq!(stat.total, None);
        assert_eq!(stat.per_cpu.len(), 1);
    }

    #[test]
    fn proc_stat_short_line_keeps_optionals_none() {
        let stat = parse_proc_stat("cpu 1 2 3 4\n");
        let total = stat.total.clone().expect("total");
        assert_eq!(total.user, Some(1));
        assert_eq!(total.iowait, None);
        assert_eq!(total.steal, None);
        assert_eq!(total.total_jiffies(), Some(10));
    }

    #[test]
    fn proc_stat_malformed_core_is_reported() {
        let stat = parse_proc_stat("cpu x 2 3 4\n");
        assert!(!stat.parse_errors.is_empty());
        assert_eq!(stat.total.expect("total").user, None);
    }

    #[test]
    fn proc_stat_total_jiffies_none_when_core_missing() {
        let times = CpuTimes {
            user: Some(1),
            ..CpuTimes::default()
        };
        assert_eq!(times.total_jiffies(), None);
    }

    #[test]
    fn guest_time_is_not_double_counted() {
        // guest/guest_nice are already part of user/nice on Linux.
        let times = CpuTimes {
            user: Some(100),
            nice: Some(20),
            system: Some(30),
            idle: Some(4000),
            iowait: Some(50),
            irq: Some(0),
            softirq: Some(10),
            steal: Some(5),
            guest: Some(40),
            guest_nice: Some(3),
        };
        assert_eq!(times.total_jiffies(), Some(4215));
    }

    #[test]
    fn total_jiffies_is_none_on_overflow_not_saturated() {
        let times = CpuTimes {
            user: Some(u64::MAX),
            nice: Some(1),
            system: Some(0),
            idle: Some(0),
            ..CpuTimes::default()
        };
        assert_eq!(times.total_jiffies(), None);
    }

    // Fictional /proc/meminfo fixture.
    const MEMINFO: &str = "\
MemTotal:       65870824 kB
MemFree:        14040696 kB
MemAvailable:   61797908 kB
Buffers:          200000 kB
Cached:          3000000 kB
SwapCached:            0 kB
SwapTotal:             0 kB
SwapFree:              0 kB
Dirty:               128 kB
Shmem:            500000 kB
Slab:             400000 kB
SReclaimable:     300000 kB
SUnreclaim:       100000 kB
HugePages_Total:       0
HugePages_Free:        0
";

    #[test]
    fn meminfo_converts_kb_to_bytes() {
        let info = parse_meminfo(MEMINFO);
        assert_eq!(info.mem_total_bytes, Some(65_870_824 * 1024));
        assert_eq!(info.mem_available_bytes, Some(61_797_908 * 1024));
        assert_eq!(info.swap_total_bytes, Some(0));
        assert_eq!(info.huge_pages_total, Some(0));
        assert!(info.parse_errors.is_empty());
    }

    #[test]
    fn meminfo_missing_field_stays_none() {
        let info = parse_meminfo("MemTotal: 100 kB\n");
        assert_eq!(info.mem_total_bytes, Some(102_400));
        assert_eq!(info.mem_available_bytes, None);
    }

    #[test]
    fn meminfo_malformed_value_is_reported_not_zero() {
        let info = parse_meminfo("MemTotal: notanumber kB\nMemFree: 5 kB\n");
        assert_eq!(info.mem_total_bytes, None);
        assert_eq!(info.mem_free_bytes, Some(5 * 1024));
        assert_eq!(info.parse_errors.len(), 1);
    }

    #[test]
    fn meminfo_parse_error_does_not_echo_source_text() {
        let info = parse_meminfo("secret=hostvalue\n");
        assert_eq!(info.parse_errors.len(), 1);
        assert!(
            info.parse_errors
                .iter()
                .all(|error| !error.contains("secret") && !error.contains("hostvalue"))
        );
    }

    // Fictional /proc/net/dev fixture.
    const NET_DEV: &str = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 109912212   38356    0    0    0     0          0         0 109912212   38356    0    0    0     0       0          0
  eth0: 12916997768 4254295    1    2    3     4          5         6 1155715126 3595150   7    8    9     10      11         12
";

    #[test]
    fn net_dev_parses_interfaces_and_skips_headers() {
        let counters = parse_net_dev(NET_DEV);
        assert_eq!(counters.interfaces.len(), 2);
        let eth0 = counters
            .interfaces
            .iter()
            .find(|interface| interface.name == "eth0")
            .expect("eth0");
        assert_eq!(eth0.rx_bytes, 12_916_997_768);
        assert_eq!(eth0.rx_errors, 1);
        assert_eq!(eth0.rx_dropped, 2);
        assert_eq!(eth0.rx_frame, 4);
        assert_eq!(eth0.rx_compressed, 5);
        assert_eq!(eth0.rx_multicast, 6);
        assert_eq!(eth0.tx_bytes, 1_155_715_126);
        assert_eq!(eth0.tx_errors, 7);
        assert_eq!(eth0.tx_dropped, 8);
        assert_eq!(eth0.tx_fifo, 9);
        assert_eq!(eth0.tx_collisions, 10);
        assert_eq!(eth0.tx_carrier, 11);
        assert_eq!(eth0.tx_compressed, 12);
        assert!(counters.parse_errors.is_empty());
    }

    #[test]
    fn net_dev_malformed_counters_are_reported() {
        let fixture =
            "Inter-|   Receive |  Transmit\n    eth0: 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15\n";
        let counters = parse_net_dev(fixture);
        assert!(counters.interfaces.is_empty());
        assert_eq!(counters.parse_errors.len(), 1);
    }

    #[test]
    fn collect_reads_ifindex_and_marks_partial_when_missing() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("proc/net")).expect("proc/net");
        std::fs::write(dir.path().join("proc/net/dev"), NET_DEV).expect("dev");
        std::fs::create_dir_all(dir.path().join("sys/class/net/eth0")).expect("sys eth0");
        std::fs::write(dir.path().join("sys/class/net/eth0/ifindex"), "2\n").expect("ifindex");

        let fs = HostFs::new(dir.path());
        let section = collect(&fs, &CollectOptions::default());
        let network = section.network.expect("network parsed");
        let eth0 = network
            .interfaces
            .iter()
            .find(|interface| interface.name == "eth0")
            .expect("eth0");
        assert_eq!(eth0.ifindex, Some(2));
        let lo = network
            .interfaces
            .iter()
            .find(|interface| interface.name == "lo")
            .expect("lo");
        assert_eq!(lo.ifindex, None);
        assert_eq!(section.network_coverage.status, CoverageStatus::Partial);
        assert!(
            section
                .network_coverage
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("ifindex"))
        );
    }

    #[test]
    fn network_view_detection() {
        assert_eq!(network_view("proc/net"), NetworkView::ProcNetSelf);
        assert_eq!(network_view("proc/1/net"), NetworkView::PidNamespace);
        assert_eq!(network_view("proc/self/net"), NetworkView::Unknown);
    }
}
