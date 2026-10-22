//! Read-only Ubuntu host collectors for Scout (first batch).
//!
//! # Scope
//!
//! This module performs a single, read-only pass over a configurable host root
//! (default [`DEFAULT_HOST_ROOT`]: `/host` in a container, `/` for a native
//! process). It never executes commands, never reads `/etc/shadow`, never reads
//! `/proc/<pid>/cmdline` or `/proc/<pid>/environ`, and never attempts network
//! scanning or vulnerability matching.
//!
//! Everything observed is reported as raw counters plus explicit coverage.
//! Missing files and parse failures are never coerced to zero: data fields are
//! `Option`s and each section carries a [`Coverage`].
//!
//! # Entry point
//!
//! ```ignore
//! let batch = collectors::collect(Path::new("/host"));
//! ```
//!
//! [`collect`] is synchronous and blocking. The caller is expected to run it on
//! a bounded blocking worker, not on the async runtime thread.
//!
//! # Required host mounts (tell DevOps)
//!
//! The collector only reads paths *relative to the host root*; a missing mount
//! yields `partial`/`missing` coverage and is never replaced by the Scout
//! container's own root. For a containerized Scout the following read-only
//! mounts are needed:
//!
//! | Host path | Container path | Used for |
//! | --- | --- | --- |
//! | `/etc/os-release` | `/host/etc/os-release` | distro id/version |
//! | `/etc/hostname` | `/host/etc/hostname` | hostname (fallback `/proc/sys/kernel/hostname`) |
//! | `/proc` | `/host/proc` | cpu, mem, net counters, PIDs, sockets, btime |
//! | `/sys` | `/host/sys` | interface kind classification (optional) |
//! | `/var/lib/dpkg` | `/host/var/lib/dpkg` | installed package database |
//! | `/etc/machine-id` | `/host/etc/machine-id` | stable host fingerprint (digest only) |
//!
//! Notes for deployment:
//!
//! * `/etc/os-release` is usually a symlink to `../usr/lib/os-release`. In-root
//!   symlinks are resolved safely; declare `/host/usr/lib/os-release` too if the
//!   symlink target lives there.
//! * `/proc/net` is a symlink to `self/net`, which resolves to the *reader's*
//!   network namespace. A plain bind mount of the host `/proc` therefore does
//!   not guarantee the host network view. To read a specific network namespace,
//!   set [`CollectOptions::network_proc_prefix`] to `proc/<pid>/net` (for
//!   example `proc/1/net` when host PID 1 is visible). Otherwise the coverage
//!   reason records that the procfs view may not be the host view.
//! * Process and package data come from `/host/proc` and `/host/var/lib/dpkg`,
//!   which intentionally excludes the Scout container's own software.
//! * `/etc/machine-id` is read only to derive
//!   [`host::fingerprint_from_machine_id`]; the raw identifier is never stored
//!   in the DTO nor logged. When the mount is absent the fingerprint is `None`
//!   and the host coverage is partial.

pub mod coverage;
pub mod host;
pub mod metrics;
pub mod packages;
pub mod ports;
pub mod processes;
pub mod safe_io;

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

pub use coverage::{Coverage, CoverageBuilder, CoverageStatus};
pub use host::{HostInfo, HostSection};
pub use metrics::{
    CpuStat, CpuTimes, InterfaceKind, Meminfo, MetricsSection, NetCounters, NetInterfaceCounters,
    NetworkView,
};
pub use packages::{OriginStatus, PackageEntry, PackagesSection};
pub use ports::{IpFamily, PortEndpoint, PortProtocol, PortsSection};
pub use processes::{ProcessEntry, ProcessSection, ProcessState};
pub use safe_io::{DEFAULT_MAX_FILE_BYTES, HostFs, MAX_DPKG_STATUS_BYTES, ReadError};

/// Schema version of the emitted DTOs. Bump when a field is removed or changes
/// meaning; additive optional fields keep the same version.
pub const SCHEMA_VERSION: u32 = 1;

/// Collector revision string, carried alongside every snapshot.
pub const COLLECTOR_REVISION: &str = "scout-collectors/0.1.0";

/// Default host root. Override with `SENTINEL_HOST_ROOT` (`/` for native).
pub const DEFAULT_HOST_ROOT: &str = "/host";

/// Default upper bound on the number of process entries read from `/proc`.
pub const DEFAULT_MAX_PROCESSES: usize = 20_000;

/// Tunables for one collection pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CollectOptions {
    /// Keep loopback endpoints in the port list. When `false`, endpoints that
    /// are loopback are dropped from `ports.endpoints` (the counters still
    /// describe the raw set). Default `true` so nothing is silently lost.
    pub include_loopback: bool,
    pub collect_host: bool,
    pub collect_metrics: bool,
    pub collect_packages: bool,
    pub collect_ports: bool,
    pub collect_processes: bool,
    /// Read the full per-PID process table, not just the counts.
    pub collect_process_table: bool,
    /// Upper bound on process entries read from `/proc`.
    pub max_processes: usize,
    /// Byte cap for small procfs/sysfs text files.
    pub max_file_bytes: u64,
    /// Byte cap for `/var/lib/dpkg/status`.
    pub max_dpkg_status_bytes: u64,
    /// Host-root-relative prefix for the network namespace to read the socket
    /// and interface counters from. Default `proc/net`; use `proc/<pid>/net` to
    /// target a specific network namespace (for example `proc/1/net`).
    pub network_proc_prefix: String,
}

impl Default for CollectOptions {
    fn default() -> Self {
        CollectOptions {
            include_loopback: true,
            collect_host: true,
            collect_metrics: true,
            collect_packages: true,
            collect_ports: true,
            collect_processes: true,
            collect_process_table: true,
            max_processes: DEFAULT_MAX_PROCESSES,
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_dpkg_status_bytes: MAX_DPKG_STATUS_BYTES,
            network_proc_prefix: "proc/net".to_string(),
        }
    }
}

/// The complete result of one read-only collection pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CollectionBatch {
    pub schema_version: u32,
    pub collector_revision: String,
    /// Wall-clock time at the start of the pass (the caller owns clock trust).
    pub observed_at_unix_seconds: i64,
    pub observed_at_nanos: u32,
    /// Host root that was read, as configured.
    pub host_root: String,
    pub host: HostSection,
    pub metrics: MetricsSection,
    pub packages: PackagesSection,
    pub ports: PortsSection,
    pub processes: ProcessSection,
}

impl Default for CollectionBatch {
    fn default() -> Self {
        CollectionBatch {
            schema_version: SCHEMA_VERSION,
            collector_revision: COLLECTOR_REVISION.to_string(),
            observed_at_unix_seconds: 0,
            observed_at_nanos: 0,
            host_root: String::new(),
            host: HostSection::default(),
            metrics: MetricsSection::default(),
            packages: PackagesSection::default(),
            ports: PortsSection::default(),
            processes: ProcessSection::default(),
        }
    }
}

impl CollectionBatch {
    /// Combined coverage across every section.
    pub fn coverage(&self) -> Coverage {
        Coverage::aggregate([
            &self.host.coverage,
            &self.metrics.coverage,
            &self.packages.coverage,
            &self.ports.coverage,
            &self.processes.coverage,
        ])
    }
}

/// Collect with default options.
pub fn collect(root: &Path) -> CollectionBatch {
    collect_with_options(root, &CollectOptions::default())
}

/// Collect with explicit options.
///
/// Reads are synchronous and bounded; no file is written and no process runs.
pub fn collect_with_options(root: &Path, options: &CollectOptions) -> CollectionBatch {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let fs = HostFs::new(root);

    let mut host = if options.collect_host {
        host::collect(&fs)
    } else {
        HostSection::skipped()
    };
    let metrics = if options.collect_metrics {
        metrics::collect(&fs, options)
    } else {
        MetricsSection::skipped()
    };
    let packages = if options.collect_packages {
        packages::collect(&fs, options)
    } else {
        PackagesSection::skipped()
    };
    let ports = if options.collect_ports {
        ports::collect(&fs, options)
    } else {
        PortsSection::skipped()
    };
    let processes = if options.collect_processes {
        processes::collect(&fs, options)
    } else {
        ProcessSection::skipped()
    };

    // Memory total and boot time live in /proc; fill the inventory from the
    // metrics section so the file is read once.
    if let Some(info) = host.info.as_mut() {
        if info.memory_total_bytes.is_none()
            && let Some(mem) = metrics.memory.as_ref()
        {
            info.memory_total_bytes = mem.mem_total_bytes;
        }
        if info.booted_at_unix_seconds.is_none()
            && let Some(cpu) = metrics.cpu.as_ref()
        {
            info.booted_at_unix_seconds = cpu.btime_unix_seconds;
        }
    }

    CollectionBatch {
        schema_version: SCHEMA_VERSION,
        collector_revision: COLLECTOR_REVISION.to_string(),
        observed_at_unix_seconds: now.as_secs() as i64,
        observed_at_nanos: now.subsec_nanos(),
        host_root: root.to_string_lossy().into_owned(),
        host,
        metrics,
        packages,
        ports,
        processes,
    }
}
