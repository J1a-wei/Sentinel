//! Bounded, read-only runtime detection. Probe the process root, never the host
//! collection root. The report contains paths and fixed reason codes only.
use crate::collectors::{HostFs, ReadError};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::{
    env, fs,
    path::{Path, PathBuf},
    time::Duration,
};

const MAX_CGROUP_BYTES: u64 = 64 * 1024;
const DEFAULT_NETWORK_PREFIX: &str = "proc/1/net";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeMode {
    Auto,
    Native,
    Container,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeKind {
    Native,
    Container,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    DockerMarker,
    ContainerenvMarker,
    SystemdContainerMarker,
    HostContainerManagerMarker,
    ContainerMarkerUnavailable,
    SelfCgroupContainer,
    Pid1CgroupContainer,
    SelfCgroupUnavailable,
    Pid1CgroupUnavailable,
    NativeCgroupHierarchy,
    RuntimeDetectionInconclusive,
    RuntimeModeExplicit,
    HostRootExplicit,
    RuntimeOverrideRequired,
    HostRootMissingOrInaccessible,
    ContainerProcessRootRefused,
    ContainerRootIdentityUnavailable,
    ContainerHostProcMissing,
    NetworkSourceMissingOrInaccessible,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RootStatus {
    Available,
    Missing,
    NotDirectory,
    Unavailable,
    NotSelected,
    RefusedProcessRoot,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceStatus {
    Available,
    MissingOrInaccessible,
    NotSelected,
}

#[derive(Debug, Serialize)]
pub struct RuntimeReport {
    pub detected_runtime: RuntimeKind,
    pub requested_mode: RuntimeMode,
    pub selected_mode: RuntimeKind,
    pub host_root: Option<PathBuf>,
    pub host_root_explicit: bool,
    pub host_root_status: RootStatus,
    pub network_proc_prefix: String,
    pub network_source: Option<PathBuf>,
    pub network_source_status: SourceStatus,
    pub collection_allowed: bool,
    pub reasons: Vec<Reason>,
}

impl RuntimeReport {
    pub fn require_collection(&self) -> Result<()> {
        ensure!(
            self.collection_allowed,
            "runtime selection prevents collection; inspect scout doctor and configure SENTINEL_RUNTIME_MODE / SENTINEL_HOST_ROOT"
        );
        Ok(())
    }
}

struct Config {
    mode: RuntimeMode,
    host_root: Option<PathBuf>,
    network_proc_prefix: String,
}

impl Config {
    fn parse(mode: Option<&str>, root: Option<&str>, network: Option<&str>) -> Result<Self> {
        let mode = match mode.unwrap_or("auto") {
            "auto" => RuntimeMode::Auto,
            "native" => RuntimeMode::Native,
            "container" => RuntimeMode::Container,
            _ => anyhow::bail!("SENTINEL_RUNTIME_MODE must be auto, native, or container"),
        };
        if let Some(root) = root {
            ensure!(
                !root.trim().is_empty()
                    && root.len() <= 4096
                    && !root.chars().any(char::is_control),
                "SENTINEL_HOST_ROOT must be a nonempty path without control characters"
            );
        }
        let network = network.unwrap_or(DEFAULT_NETWORK_PREFIX);
        ensure!(
            !network.is_empty()
                && network.len() <= 256
                && !network.chars().any(char::is_control)
                && !Path::new(network).is_absolute()
                && network
                    .split('/')
                    .all(|part| !part.is_empty() && part != "." && part != ".."),
            "SENTINEL_NETWORK_PROC_PREFIX must be a nonempty relative path without empty, dot, or parent components"
        );
        Ok(Self {
            mode,
            host_root: root.map(PathBuf::from),
            network_proc_prefix: network.into(),
        })
    }

    fn from_env() -> Result<Self> {
        fn optional(name: &str) -> Result<Option<String>> {
            match env::var(name) {
                Ok(value) => Ok(Some(value)),
                Err(env::VarError::NotPresent) => Ok(None),
                Err(env::VarError::NotUnicode(_)) => anyhow::bail!("{name} must be valid UTF-8"),
            }
        }
        Self::parse(
            optional("SENTINEL_RUNTIME_MODE")?.as_deref(),
            optional("SENTINEL_HOST_ROOT")?.as_deref(),
            optional("SENTINEL_NETWORK_PROC_PREFIX")?.as_deref(),
        )
    }
}

pub async fn inspect_current() -> Result<RuntimeReport> {
    let config = Config::from_env()?;
    tokio::time::timeout(
        Duration::from_secs(5),
        tokio::task::spawn_blocking(move || inspect(config, Path::new("/"))),
    )
    .await
    .context("runtime detection deadline exceeded")?
    .context("runtime detection worker stopped")
}

struct Detection {
    kind: RuntimeKind,
    reasons: Vec<Reason>,
}

enum Probe {
    Absent,
    Text(String),
    Unavailable,
}

fn read_probe(reader: &HostFs, path: &str, limit: u64) -> Probe {
    // Refuse non-regular endpoints before opening, including named pipes. The
    // process filesystem is trusted; HostFs also bounds and confines the read.
    match fs::symlink_metadata(reader.root().join(path)) {
        Ok(meta) if meta.is_file() => {}
        Ok(_) => return Probe::Unavailable,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Probe::Absent,
        Err(_) => return Probe::Unavailable,
    }
    match reader.read_to_string(path, Some(limit)) {
        Ok(text) => Probe::Text(text),
        Err(ReadError::NotFound) => Probe::Absent,
        Err(_) => Probe::Unavailable,
    }
}

#[derive(Default)]
struct CgroupEvidence {
    container: bool,
    native_hierarchy: bool,
}

fn cgroup_evidence(text: &str) -> Option<CgroupEvidence> {
    let mut result = CgroupEvidence::default();
    let mut count = 0;
    for line in text.lines() {
        count += 1;
        if count > 128 {
            return None;
        }
        let mut parts = line.splitn(3, ':');
        let hierarchy = parts.next()?;
        let controllers = parts.next()?;
        let path = parts.next()?;
        if hierarchy.is_empty()
            || !hierarchy.bytes().all(|b| b.is_ascii_digit())
            || !controllers
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b",_=-".contains(&b))
            || !path.starts_with('/')
            || path.chars().any(char::is_control)
            || path.split('/').any(|part| part == "." || part == "..")
        {
            return None;
        }
        result.container |= path.split('/').any(|part| {
            matches!(
                part,
                "docker" | "libpod" | "kubepods" | "kubepods.slice" | "lxc" | "lxc.payload"
            ) || part.starts_with("kubepods-") && part.ends_with(".slice")
                || part.starts_with("lxc.payload.")
                || ["docker-", "libpod-", "cri-containerd-", "crio-"]
                    .iter()
                    .any(|prefix| part.starts_with(prefix) && part.ends_with(".scope"))
        });
        result.native_hierarchy |= path.starts_with("/system.slice/")
            || path.starts_with("/user.slice/")
            || path == "/init.scope";
    }
    (count > 0).then_some(result)
}

fn detect(process_root: &Path) -> Detection {
    let reader = HostFs::new(process_root);
    let mut reasons = Vec::new();
    let mut container = false;
    let mut markers_known = true;
    for (path, reason) in [
        (".dockerenv", Reason::DockerMarker),
        ("run/.containerenv", Reason::ContainerenvMarker),
    ] {
        match fs::symlink_metadata(process_root.join(path)) {
            Ok(meta) if meta.is_file() => {
                container = true;
                reasons.push(reason);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => {
                markers_known = false;
            }
        }
    }
    for (path, reason) in [
        ("run/systemd/container", Reason::SystemdContainerMarker),
        (
            "run/host/container-manager",
            Reason::HostContainerManagerMarker,
        ),
    ] {
        match read_probe(&reader, path, 256) {
            Probe::Text(value) if !value.trim().is_empty() => {
                container = true;
                reasons.push(reason);
            }
            Probe::Absent => {}
            _ => {
                markers_known = false;
            }
        }
    }
    if !markers_known {
        reasons.push(Reason::ContainerMarkerUnavailable);
    }
    let mut native = false;
    for (path, positive, unavailable) in [
        (
            "proc/self/cgroup",
            Reason::SelfCgroupContainer,
            Reason::SelfCgroupUnavailable,
        ),
        (
            "proc/1/cgroup",
            Reason::Pid1CgroupContainer,
            Reason::Pid1CgroupUnavailable,
        ),
    ] {
        let evidence = match read_probe(&reader, path, MAX_CGROUP_BYTES) {
            Probe::Text(value) => cgroup_evidence(&value),
            _ => None,
        };
        match evidence {
            Some(evidence) => {
                if evidence.container {
                    container = true;
                    reasons.push(positive);
                }
                if path == "proc/self/cgroup" {
                    native = evidence.native_hierarchy;
                }
            }
            None => reasons.push(unavailable),
        }
    }
    let kind = if container {
        RuntimeKind::Container
    } else if markers_known && native {
        reasons.push(Reason::NativeCgroupHierarchy);
        RuntimeKind::Native
    } else {
        reasons.push(Reason::RuntimeDetectionInconclusive);
        RuntimeKind::Unknown
    };
    Detection { kind, reasons }
}

fn select(config: Config, detection: Detection) -> RuntimeReport {
    let selected = match config.mode {
        RuntimeMode::Auto => detection.kind,
        RuntimeMode::Native => RuntimeKind::Native,
        RuntimeMode::Container => RuntimeKind::Container,
    };
    let explicit_root = config.host_root.is_some();
    let root = config.host_root.or_else(|| match selected {
        RuntimeKind::Native => Some(PathBuf::from("/")),
        RuntimeKind::Container => Some(PathBuf::from("/host")),
        RuntimeKind::Unknown => None,
    });
    let mut reasons = detection.reasons;
    if config.mode != RuntimeMode::Auto {
        reasons.push(Reason::RuntimeModeExplicit);
    }
    if explicit_root {
        reasons.push(Reason::HostRootExplicit);
    }
    if root.is_none() {
        reasons.push(Reason::RuntimeOverrideRequired);
    }
    RuntimeReport {
        detected_runtime: detection.kind,
        requested_mode: config.mode,
        selected_mode: selected,
        network_source: root.as_ref().map(|p| p.join(&config.network_proc_prefix)),
        network_proc_prefix: config.network_proc_prefix,
        host_root: root,
        host_root_explicit: explicit_root,
        host_root_status: RootStatus::NotSelected,
        network_source_status: SourceStatus::NotSelected,
        collection_allowed: false,
        reasons,
    }
}

fn same_directory(left: &Path, right: &Path) -> std::io::Result<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let left = fs::metadata(left)?;
        let right = fs::metadata(right)?;
        // Also detects a bind mount of this very process root at /host.
        Ok(left.dev() == right.dev() && left.ino() == right.ino())
    }
    #[cfg(not(unix))]
    {
        Ok(fs::canonicalize(left)? == fs::canonicalize(right)?)
    }
}

fn source_directory(reader: &HostFs, relative: &str) -> bool {
    reader.entry_exists(relative)
        && fs::metadata(reader.root().join(relative)).is_ok_and(|meta| meta.is_dir())
}

fn inspect(config: Config, process_root: &Path) -> RuntimeReport {
    let mut report = select(config, detect(process_root));
    let Some(root) = &report.host_root else {
        return report;
    };
    report.host_root_status = match fs::metadata(root) {
        Ok(meta) if meta.is_dir() => RootStatus::Available,
        Ok(_) => RootStatus::NotDirectory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => RootStatus::Missing,
        Err(_) => RootStatus::Unavailable,
    };
    if report.host_root_status != RootStatus::Available {
        report.reasons.push(Reason::HostRootMissingOrInaccessible);
        return report;
    }
    let container = report.detected_runtime == RuntimeKind::Container
        || report.selected_mode == RuntimeKind::Container;
    if container {
        match same_directory(root, process_root) {
            Ok(false) => {}
            Ok(true) => {
                report.host_root_status = RootStatus::RefusedProcessRoot;
                report.reasons.push(Reason::ContainerProcessRootRefused);
                return report;
            }
            Err(_) => {
                report.host_root_status = RootStatus::Unavailable;
                report
                    .reasons
                    .push(Reason::ContainerRootIdentityUnavailable);
                return report;
            }
        }
    }
    let host_reader = HostFs::new(root);
    let proc_available = source_directory(&host_reader, "proc");
    if container && !proc_available {
        report.reasons.push(Reason::ContainerHostProcMissing);
    }
    report.network_source_status = if source_directory(&host_reader, &report.network_proc_prefix) {
        SourceStatus::Available
    } else {
        report
            .reasons
            .push(Reason::NetworkSourceMissingOrInaccessible);
        SourceStatus::MissingOrInaccessible
    };
    report.collection_allowed = !container || proc_available;
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(root: &Path, relative: &str, value: impl AsRef<[u8]>) -> Result<()> {
        let target = root.join(relative);
        fs::create_dir_all(target.parent().context("fixture parent")?)?;
        fs::write(target, value)?;
        Ok(())
    }

    fn native_fixture() -> Result<tempfile::TempDir> {
        let root = tempfile::tempdir()?;
        write(
            root.path(),
            "proc/self/cgroup",
            "0::/system.slice/sentinel-scout.service\n",
        )?;
        write(root.path(), "proc/1/cgroup", "0::/init.scope\n")?;
        Ok(root)
    }

    fn host_fixture() -> Result<tempfile::TempDir> {
        let root = tempfile::tempdir()?;
        fs::create_dir_all(root.path().join(DEFAULT_NETWORK_PREFIX))?;
        Ok(root)
    }

    #[test]
    fn native_defaults_require_known_markers_and_supported_cgroup() -> Result<()> {
        let process = native_fixture()?;
        let detection = detect(process.path());
        assert_eq!(detection.kind, RuntimeKind::Native);
        let report = select(Config::parse(None, None, None)?, detection);
        assert_eq!(report.requested_mode, RuntimeMode::Auto);
        assert_eq!(report.selected_mode, RuntimeKind::Native);
        assert_eq!(report.host_root.as_deref(), Some(Path::new("/")));
        assert_eq!(
            report.network_source.as_deref(),
            Some(Path::new("/proc/1/net"))
        );
        assert!(report.reasons.contains(&Reason::NativeCgroupHierarchy));
        Ok(())
    }

    #[test]
    fn runtime_markers_win_even_with_host_pid_and_native_cgroup() -> Result<()> {
        for (marker, value, reason) in [
            (".dockerenv", "", Reason::DockerMarker),
            ("run/.containerenv", "", Reason::ContainerenvMarker),
            (
                "run/systemd/container",
                "systemd-nspawn\n",
                Reason::SystemdContainerMarker,
            ),
            (
                "run/host/container-manager",
                "podman\n",
                Reason::HostContainerManagerMarker,
            ),
        ] {
            let process = native_fixture()?;
            write(process.path(), marker, value)?;
            let detection = detect(process.path());
            assert_eq!(detection.kind, RuntimeKind::Container);
            assert!(detection.reasons.contains(&reason));
            let report = select(Config::parse(None, None, None)?, detection);
            assert_eq!(report.host_root.as_deref(), Some(Path::new("/host")));
            assert_eq!(
                report.network_source.as_deref(),
                Some(Path::new("/host/proc/1/net"))
            );
        }
        Ok(())
    }

    #[test]
    fn cgroup_v1_and_v2_container_paths_are_recognized() -> Result<()> {
        for content in [
            "12:cpu,cpuacct:/docker/fictional-id\n",
            "0::/system.slice/docker-fictional.scope\n",
            "0::/kubepods/besteffort/pod-fixture/fictional\n",
            "0::/kubepods.slice/kubepods-burstable.slice/pod-fixture/cri-containerd-fictional.scope\n",
            "0::/system.slice/crio-fictional.scope\n",
            "0::/user.slice/user-1000.slice/libpod-fictional.scope\n",
            "1:name=systemd:/lxc/fictional\n",
            "0::/lxc.payload.fictional\n",
        ] {
            let process = tempfile::tempdir()?;
            write(process.path(), "proc/self/cgroup", content)?;
            let detection = detect(process.path());
            assert_eq!(detection.kind, RuntimeKind::Container);
            assert!(detection.reasons.contains(&Reason::SelfCgroupContainer));
        }
        // A daemon service name alone does not mean Scout is in that container.
        for content in [
            "0::/system.slice/docker.service\n",
            "0::/system.slice/containerd.service\n",
        ] {
            let evidence = cgroup_evidence(content).context("valid fixture")?;
            assert!(!evidence.container);
        }
        Ok(())
    }

    #[test]
    fn pid1_container_evidence_is_not_lost_when_self_path_is_hidden() -> Result<()> {
        let process = tempfile::tempdir()?;
        write(process.path(), "proc/self/cgroup", "0::/\n")?;
        write(
            process.path(),
            "proc/1/cgroup",
            "0::/system.slice/docker-fictional.scope\n",
        )?;
        let detection = detect(process.path());
        assert_eq!(detection.kind, RuntimeKind::Container);
        assert!(detection.reasons.contains(&Reason::Pid1CgroupContainer));
        Ok(())
    }

    #[test]
    fn missing_masked_malformed_and_oversized_evidence_stays_unknown() -> Result<()> {
        for content in [
            None,
            Some("".to_owned()),
            Some("0::/\n".into()),
            Some("malformed-fictional-private-detail\n".into()),
            Some("0::/custom-unrecognized-scope\n".into()),
            Some("x".repeat(MAX_CGROUP_BYTES as usize + 1)),
        ] {
            let process = tempfile::tempdir()?;
            if let Some(content) = content {
                write(process.path(), "proc/self/cgroup", content)?;
            }
            let report = inspect(Config::parse(None, None, None)?, process.path());
            assert_eq!(report.detected_runtime, RuntimeKind::Unknown);
            assert_eq!(report.host_root, None);
            assert_eq!(report.network_source, None);
            assert!(!report.collection_allowed);
            assert!(report.require_collection().is_err());
            assert!(report.reasons.contains(&Reason::RuntimeOverrideRequired));
        }
        Ok(())
    }

    #[test]
    fn inaccessible_or_invalid_probes_do_not_become_native() -> Result<()> {
        let process = native_fixture()?;
        fs::create_dir(process.path().join(".dockerenv"))?;
        assert_eq!(detect(process.path()).kind, RuntimeKind::Unknown);
        fs::remove_dir(process.path().join(".dockerenv"))?;
        write(process.path(), "run/systemd/container", "")?;
        assert_eq!(detect(process.path()).kind, RuntimeKind::Unknown);
        fs::remove_file(process.path().join("run/systemd/container"))?;
        write(process.path(), "proc/self/cgroup", [0xff, 0xfe])?;
        assert_eq!(detect(process.path()).kind, RuntimeKind::Unknown);
        Ok(())
    }

    #[test]
    fn explicit_modes_select_defaults_without_hiding_detection() -> Result<()> {
        let process = tempfile::tempdir()?;
        for (mode, selected, root) in [
            ("native", RuntimeKind::Native, "/"),
            ("container", RuntimeKind::Container, "/host"),
        ] {
            let report = select(
                Config::parse(Some(mode), None, None)?,
                detect(process.path()),
            );
            assert_eq!(report.detected_runtime, RuntimeKind::Unknown);
            assert_eq!(report.selected_mode, selected);
            assert_eq!(report.host_root.as_deref(), Some(Path::new(root)));
            assert!(report.reasons.contains(&Reason::RuntimeModeExplicit));
        }
        Ok(())
    }

    #[test]
    fn explicit_root_wins_and_host_markers_do_not_affect_detection() -> Result<()> {
        let process = native_fixture()?;
        let host = host_fixture()?;
        write(host.path(), ".dockerenv", "")?;
        let report = inspect(
            Config::parse(None, host.path().to_str(), None)?,
            process.path(),
        );
        assert_eq!(report.detected_runtime, RuntimeKind::Native);
        assert_eq!(report.host_root.as_deref(), Some(host.path()));
        assert!(report.host_root_explicit && report.collection_allowed);
        assert_eq!(report.network_source_status, SourceStatus::Available);
        // An explicit fixture also resolves an otherwise unknown runtime.
        let unknown = tempfile::tempdir()?;
        let report = inspect(
            Config::parse(None, host.path().to_str(), None)?,
            unknown.path(),
        );
        assert_eq!(report.selected_mode, RuntimeKind::Unknown);
        assert!(report.collection_allowed);
        Ok(())
    }

    #[test]
    fn explicit_missing_root_never_falls_back_or_creates_files() -> Result<()> {
        let process = native_fixture()?;
        let parent = tempfile::tempdir()?;
        let missing = parent.path().join("missing");
        for mode in ["auto", "native", "container"] {
            let report = inspect(
                Config::parse(Some(mode), missing.to_str(), None)?,
                process.path(),
            );
            assert_eq!(report.host_root.as_deref(), Some(missing.as_path()));
            assert_eq!(report.host_root_status, RootStatus::Missing);
            assert!(!report.collection_allowed);
        }
        assert_eq!(fs::read_dir(parent.path())?.count(), 0);
        Ok(())
    }

    #[test]
    fn detected_container_cannot_be_forced_to_collect_its_own_root() -> Result<()> {
        let process = native_fixture()?;
        write(process.path(), ".dockerenv", "")?;
        for mode in ["auto", "native", "container"] {
            let report = inspect(
                Config::parse(Some(mode), process.path().to_str(), None)?,
                process.path(),
            );
            assert_eq!(report.host_root_status, RootStatus::RefusedProcessRoot);
            assert!(!report.collection_allowed);
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn container_root_alias_is_also_refused() -> Result<()> {
        let process = native_fixture()?;
        let parent = tempfile::tempdir()?;
        let alias = parent.path().join("host");
        std::os::unix::fs::symlink(process.path(), &alias)?;
        let report = inspect(
            Config::parse(Some("container"), alias.to_str(), None)?,
            process.path(),
        );
        assert_eq!(report.host_root_status, RootStatus::RefusedProcessRoot);
        assert!(!report.collection_allowed);
        Ok(())
    }

    #[test]
    fn missing_container_proc_is_blocked_and_network_override_never_falls_back() -> Result<()> {
        let process = native_fixture()?;
        write(process.path(), ".dockerenv", "")?;
        let host = tempfile::tempdir()?;
        let config = || Config::parse(None, host.path().to_str(), Some("proc/77/net"));
        let report = inspect(config()?, process.path());
        assert!(!report.collection_allowed);
        assert!(report.reasons.contains(&Reason::ContainerHostProcMissing));
        fs::create_dir_all(host.path().join("proc/1/net"))?;
        let report = inspect(config()?, process.path());
        assert!(report.collection_allowed);
        assert_eq!(
            report.network_source_status,
            SourceStatus::MissingOrInaccessible
        );
        assert_eq!(report.network_source, Some(host.path().join("proc/77/net")));
        fs::create_dir_all(host.path().join("proc/77/net"))?;
        assert_eq!(
            inspect(config()?, process.path()).network_source_status,
            SourceStatus::Available
        );
        Ok(())
    }

    #[test]
    fn settings_reject_invalid_modes_roots_and_network_traversal() {
        for mode in ["", "AUTO", "docker", "native\n"] {
            assert!(Config::parse(Some(mode), None, None).is_err());
        }
        for root in ["", " ", "/host\0", "/host\n"] {
            assert!(Config::parse(None, Some(root), None).is_err());
        }
        for network in [
            "",
            "/proc/1/net",
            ".",
            "..",
            "proc/../net",
            "proc/./net",
            "proc//net",
            "proc/net/",
            "proc/net\0",
        ] {
            assert!(Config::parse(None, None, Some(network)).is_err());
        }
        for network in ["proc/1/net", "proc/net", "proc/self/net", "proc/42/net"] {
            assert!(Config::parse(None, None, Some(network)).is_ok());
        }
    }

    #[test]
    fn report_never_contains_raw_marker_or_cgroup_text() -> Result<()> {
        let process = native_fixture()?;
        write(
            process.path(),
            "run/systemd/container",
            "fictional-private-runtime-value",
        )?;
        write(
            process.path(),
            "proc/self/cgroup",
            "0::/docker/fictional-private-cgroup-value\n",
        )?;
        let report = select(Config::parse(None, None, None)?, detect(process.path()));
        let encoded = serde_json::to_string(&report)?;
        assert!(!encoded.contains("fictional-private"));
        assert_eq!(report.detected_runtime, RuntimeKind::Container);
        assert!(report.reasons.len() < 16);
        Ok(())
    }
}
