//! Host identity and fingerprint collection: os-release, hostname, kernel,
//! architecture, CPU model/count and boot id. Memory total and boot time are
//! sourced from `/proc` by the metrics section and merged by the caller.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::coverage::{Coverage, CoverageBuilder};
use super::safe_io::HostFs;

/// Maximum accepted length for a hostname or CPU model string.
const MAX_TEXT_LEN: usize = 512;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct OsRelease {
    pub id: Option<String>,
    pub version_id: Option<String>,
    pub version_codename: Option<String>,
    pub pretty_name: Option<String>,
    pub name: Option<String>,
    pub parse_errors: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CpuInfo {
    pub logical_cpu_count: Option<u32>,
    pub model_name: Option<String>,
    pub parse_errors: Vec<String>,
}

/// Inventory fields. `None` means "not observed"; it is never a measured zero.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct HostInfo {
    pub hostname: Option<String>,
    pub hostname_source: Option<String>,
    pub os_id: Option<String>,
    pub os_version: Option<String>,
    pub os_codename: Option<String>,
    pub os_pretty_name: Option<String>,
    pub os_name: Option<String>,
    pub kernel_version: Option<String>,
    pub architecture: Option<String>,
    pub architecture_source: Option<String>,
    pub cpu_model: Option<String>,
    pub logical_cpu_count: Option<u32>,
    pub memory_total_bytes: Option<u64>,
    pub boot_id: Option<String>,
    pub booted_at_unix_seconds: Option<i64>,
    /// Domain-separated digest of the host `machine-id`. The raw identifier is
    /// never stored in the DTO or logged; `None` means it was not observed.
    pub fingerprint_sha256: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct HostSection {
    pub coverage: Coverage,
    pub info: Option<HostInfo>,
}

impl HostSection {
    pub fn skipped() -> Self {
        HostSection {
            coverage: Coverage::not_applicable("host collector disabled"),
            info: None,
        }
    }
}

/// Parse an os-release style `KEY=VALUE` document.
pub fn parse_os_release(input: &str) -> OsRelease {
    let mut out = OsRelease::default();
    for (index, raw) in input.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            out.parse_errors
                .push(format!("line {}: missing '='", index + 1));
            continue;
        };
        let key = key.trim();
        let value = unquote(value.trim());
        match key {
            "ID" => out.id = Some(value),
            "VERSION_ID" => out.version_id = Some(value),
            "VERSION_CODENAME" => out.version_codename = Some(value),
            "PRETTY_NAME" => out.pretty_name = Some(value),
            "NAME" => out.name = Some(value),
            _ => {}
        }
    }
    out
}

fn unquote(value: &str) -> String {
    let bytes = value.as_bytes();
    let quoted = bytes.len() >= 2
        && ((bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\''));
    if !quoted {
        return value.to_string();
    }
    let inner = &value[1..value.len() - 1];
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some('"') => out.push('"'),
                Some('\\') => out.push('\\'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(ch);
        }
    }
    out
}

/// Parse `/proc/cpuinfo` for the logical processor count and a model string.
pub fn parse_cpuinfo(input: &str) -> CpuInfo {
    let mut count: u32 = 0;
    let mut model: Option<String> = None;
    let mut errors = Vec::new();

    for (index, raw) in input.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();

        if key == "processor" {
            match value.parse::<u32>() {
                Ok(_) => count += 1,
                Err(_) => errors.push(format!("line {}: non-numeric processor id", index + 1)),
            }
        } else if model.is_none()
            && matches!(
                key,
                "model name" | "Model" | "Hardware" | "Processor" | "cpu model"
            )
            && !value.is_empty()
        {
            model = Some(truncate(value, MAX_TEXT_LEN));
        }
    }

    CpuInfo {
        logical_cpu_count: if count > 0 { Some(count) } else { None },
        model_name: model,
        parse_errors: errors,
    }
}

fn truncate(value: &str, max: usize) -> String {
    if value.len() <= max {
        return value.to_string();
    }
    let mut end = max;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

/// Validate and normalise a `/proc/sys/kernel/random/boot_id` value.
pub fn parse_boot_id(input: &str) -> Option<String> {
    let value = input.trim();
    if value.len() != 36 {
        return None;
    }
    let valid = value.chars().enumerate().all(|(index, ch)| {
        if matches!(index, 8 | 13 | 18 | 23) {
            ch == '-'
        } else {
            ch.is_ascii_hexdigit()
        }
    });
    if valid {
        Some(value.to_ascii_lowercase())
    } else {
        None
    }
}

/// Normalise a `/etc/machine-id` value to its canonical 32 lowercase hex form.
pub fn parse_machine_id(input: &str) -> Option<String> {
    let value = input.trim();
    if value.len() != 32 || !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return None;
    }
    Some(value.to_ascii_lowercase())
}

/// Derive the stable host fingerprint from a machine-id value.
///
/// The digest is domain-separated (`sentinel:machine-id:v1` plus a NUL) so it
/// cannot be confused with a bare SHA-256 of the identifier. Only the digest is
/// returned; the raw value must not enter a DTO or a log.
pub fn fingerprint_from_machine_id(machine_id: &str) -> Option<String> {
    let normalized = parse_machine_id(machine_id)?;
    let mut hasher = Sha256::new();
    hasher.update(b"sentinel:machine-id:v1\0");
    hasher.update(normalized.as_bytes());
    Some(hex::encode(hasher.finalize()))
}

/// Parse the `btime` field of `/proc/stat` (seconds since the Unix epoch).
pub fn parse_btime(input: &str) -> Option<i64> {
    for raw in input.lines() {
        let line = raw.trim();
        let Some(rest) = line.strip_prefix("btime") else {
            continue;
        };
        let rest = rest.trim_start();
        if let Ok(value) = rest.parse::<i64>()
            && value > 0
        {
            return Some(value);
        }
    }
    None
}

/// Map the collector build target to a Debian architecture name.
fn map_build_arch(arch: &str) -> Option<String> {
    let mapped = match arch {
        "x86_64" => "amd64",
        "x86" => "i386",
        "aarch64" => "arm64",
        "arm" => "armhf",
        "powerpc64" => "ppc64el",
        "powerpc" => "powerpc",
        "riscv64" => "riscv64",
        "s390x" => "s390x",
        "mips64" => "mips64el",
        "mips" => "mipsel",
        other => other,
    };
    Some(mapped.to_string())
}

fn valid_arch(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
}

/// Read one of several candidate files, taking the first that exists.
///
/// `Ok((text, path))` on success, `Err((reason, was_not_found))` when none
/// worked. A non-`NotFound` error on the first candidate is reported, but a
/// later candidate is still tried.
fn read_first(
    fs: &HostFs,
    candidates: &[&'static str],
) -> Result<(String, &'static str), (String, bool)> {
    let mut first_error: Option<String> = None;
    for candidate in candidates {
        match fs.read_to_string(candidate, None) {
            Ok(text) => return Ok((text, candidate)),
            Err(err) if err.is_not_found() => {}
            Err(err) => {
                if first_error.is_none() {
                    first_error = Some(err.as_reason(candidate));
                }
            }
        }
    }
    match first_error {
        Some(reason) => Err((reason, false)),
        None => Err((format!("{}: not found", candidates.join(", ")), true)),
    }
}

fn detect_architecture(fs: &HostFs) -> (Option<String>, Option<String>, Vec<String>) {
    let mut errors = Vec::new();
    match fs.read_to_string("var/lib/dpkg/arch", None) {
        Ok(text) => {
            if let Some(value) = text
                .lines()
                .map(str::trim)
                .find(|line| !line.is_empty() && valid_arch(line))
            {
                return (
                    Some(value.to_string()),
                    Some("dpkg_arch".to_string()),
                    errors,
                );
            }
        }
        Err(err) if err.is_not_found() => {}
        Err(err) => errors.push(err.as_reason("var/lib/dpkg/arch")),
    }

    match map_build_arch(std::env::consts::ARCH) {
        Some(arch) => (
            Some(arch),
            Some("collector_build_target".to_string()),
            errors,
        ),
        None => (None, None, errors),
    }
}

/// Collect host identity data from the configured host root.
pub fn collect(fs: &HostFs) -> HostSection {
    let mut builder = CoverageBuilder::new();
    let mut info = HostInfo::default();
    let mut any = false;

    // os-release: /etc/os-release is normally a symlink to ../usr/lib/os-release.
    builder.source("etc/os-release");
    if !fs.entry_exists("etc/os-release") {
        builder.source("usr/lib/os-release");
    }
    match read_first(fs, &["etc/os-release", "usr/lib/os-release"]) {
        Ok((text, source)) => {
            let parsed = parse_os_release(&text);
            for error in &parsed.parse_errors {
                builder.error(format!("{source}: {error}"));
            }
            info.os_id = parsed.id;
            info.os_version = parsed.version_id;
            info.os_codename = parsed.version_codename;
            info.os_pretty_name = parsed.pretty_name;
            info.os_name = parsed.name;
            any = true;
            builder.success();
        }
        Err((reason, not_found)) => {
            if not_found {
                builder.missing(reason);
            } else {
                builder.error(reason);
            }
        }
    }

    // hostname
    builder.source("etc/hostname");
    builder.source("proc/sys/kernel/hostname");
    match read_first(fs, &["etc/hostname", "proc/sys/kernel/hostname"]) {
        Ok((text, source)) => {
            let value = truncate(text.trim(), MAX_TEXT_LEN);
            if !value.is_empty() {
                info.hostname = Some(value);
                info.hostname_source = Some(source.to_string());
                any = true;
            }
            builder.success();
        }
        Err((reason, not_found)) => {
            if not_found {
                builder.missing(reason);
            } else {
                builder.error(reason);
            }
        }
    }

    // kernel version
    builder.source("proc/sys/kernel/osrelease");
    match fs.read_to_string("proc/sys/kernel/osrelease", None) {
        Ok(text) => {
            let value = truncate(text.trim(), MAX_TEXT_LEN);
            if !value.is_empty() {
                info.kernel_version = Some(value);
                any = true;
            }
            builder.success();
        }
        Err(err) if err.is_not_found() => {
            builder.missing(err.as_reason("proc/sys/kernel/osrelease"))
        }
        Err(err) => builder.error(err.as_reason("proc/sys/kernel/osrelease")),
    }

    // cpuinfo
    builder.source("proc/cpuinfo");
    match fs.read_to_string("proc/cpuinfo", None) {
        Ok(text) => {
            let parsed = parse_cpuinfo(&text);
            for error in &parsed.parse_errors {
                builder.error(format!("proc/cpuinfo: {error}"));
            }
            if parsed.logical_cpu_count.is_some() || parsed.model_name.is_some() {
                any = true;
            }
            info.logical_cpu_count = parsed.logical_cpu_count;
            info.cpu_model = parsed.model_name;
            builder.success();
        }
        Err(err) if err.is_not_found() => builder.missing(err.as_reason("proc/cpuinfo")),
        Err(err) => builder.error(err.as_reason("proc/cpuinfo")),
    }

    // boot id
    builder.source("proc/sys/kernel/random/boot_id");
    match fs.read_to_string("proc/sys/kernel/random/boot_id", None) {
        Ok(text) => match parse_boot_id(&text) {
            Some(boot_id) => {
                info.boot_id = Some(boot_id);
                any = true;
                builder.success();
            }
            None => builder.error("proc/sys/kernel/random/boot_id: malformed uuid"),
        },
        Err(err) if err.is_not_found() => {
            builder.missing(err.as_reason("proc/sys/kernel/random/boot_id"))
        }
        Err(err) => builder.error(err.as_reason("proc/sys/kernel/random/boot_id")),
    }

    // machine-id fingerprint: the raw identifier is read but only its digest
    // is retained. The original value never enters the DTO or a reason string.
    builder.source("etc/machine-id");
    match fs.read_to_string("etc/machine-id", None) {
        Ok(text) => match fingerprint_from_machine_id(&text) {
            Some(fingerprint) => {
                info.fingerprint_sha256 = Some(fingerprint);
                any = true;
                builder.success();
            }
            None => builder.error("etc/machine-id: not a 32-hex identifier"),
        },
        Err(err) if err.is_not_found() => builder.missing(err.as_reason("etc/machine-id")),
        Err(err) => builder.error(err.as_reason("etc/machine-id")),
    }

    // architecture
    builder.source("var/lib/dpkg/arch");
    let (arch, arch_source, arch_errors) = detect_architecture(fs);
    for error in arch_errors {
        builder.error(error);
    }
    if let Some(arch) = arch {
        info.architecture = Some(arch);
        info.architecture_source = arch_source;
        any = true;
        builder.success();
    } else {
        builder.missing("architecture: no dpkg arch file and unknown build target");
    }

    HostSection {
        coverage: builder.finish(),
        info: if any { Some(info) } else { None },
    }
}

/// Paths consulted by the host collector, for documentation and tests.
pub fn sources() -> Vec<PathBuf> {
    [
        "etc/os-release",
        "usr/lib/os-release",
        "etc/hostname",
        "proc/sys/kernel/hostname",
        "proc/sys/kernel/osrelease",
        "proc/cpuinfo",
        "proc/sys/kernel/random/boot_id",
        "etc/machine-id",
        "var/lib/dpkg/arch",
    ]
    .iter()
    .map(PathBuf::from)
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fictional Ubuntu 22.04 fixture.
    const UBUNTU_2204: &str = "\
PRETTY_NAME=\"Ubuntu 22.04.5 LTS\"
NAME=\"Ubuntu\"
VERSION_ID=\"22.04\"
VERSION=\"22.04.5 LTS (Jammy Jellyfish)\"
VERSION_CODENAME=jammy
ID=ubuntu
ID_LIKE=debian
";

    // Fictional Ubuntu 24.04 fixture.
    const UBUNTU_2404: &str = "\
PRETTY_NAME=\"Ubuntu 24.04.1 LTS\"
NAME=\"Ubuntu\"
VERSION_ID=\"24.04\"
VERSION=\"24.04.1 LTS (Noble Numbat)\"
VERSION_CODENAME=noble
ID=ubuntu
ID_LIKE=debian
";

    #[test]
    fn os_release_ubuntu_2204() {
        let parsed = parse_os_release(UBUNTU_2204);
        assert_eq!(parsed.id.as_deref(), Some("ubuntu"));
        assert_eq!(parsed.version_id.as_deref(), Some("22.04"));
        assert_eq!(parsed.version_codename.as_deref(), Some("jammy"));
        assert_eq!(parsed.pretty_name.as_deref(), Some("Ubuntu 22.04.5 LTS"));
        assert!(parsed.parse_errors.is_empty());
    }

    #[test]
    fn os_release_ubuntu_2404() {
        let parsed = parse_os_release(UBUNTU_2404);
        assert_eq!(parsed.id.as_deref(), Some("ubuntu"));
        assert_eq!(parsed.version_id.as_deref(), Some("24.04"));
        assert_eq!(parsed.version_codename.as_deref(), Some("noble"));
    }

    #[test]
    fn os_release_partial_and_malformed() {
        let parsed = parse_os_release("ID=ubuntu\nBROKEN LINE\nVERSION_ID=\"22.04\"\n");
        assert_eq!(parsed.id.as_deref(), Some("ubuntu"));
        assert_eq!(parsed.version_id.as_deref(), Some("22.04"));
        assert_eq!(parsed.parse_errors.len(), 1);
    }

    #[test]
    fn os_release_empty_is_all_none() {
        let parsed = parse_os_release("");
        assert_eq!(parsed, OsRelease::default());
    }

    #[test]
    fn cpuinfo_x86_64_counts_processors() {
        let fixture = "\
processor\t: 0
model name\t: Intel(R) Xeon(R) Gold 6248 CPU @ 2.50GHz
processor\t: 1
model name\t: Intel(R) Xeon(R) Gold 6248 CPU @ 2.50GHz
";
        let parsed = parse_cpuinfo(fixture);
        assert_eq!(parsed.logical_cpu_count, Some(2));
        assert_eq!(
            parsed.model_name.as_deref(),
            Some("Intel(R) Xeon(R) Gold 6248 CPU @ 2.50GHz")
        );
    }

    #[test]
    fn cpuinfo_arm_uses_hardware_field() {
        let fixture = "\
processor\t: 0
BogoMIPS\t: 38.40
Features\t: fp asimd
Hardware\t: BCM2711
processor\t: 1
";
        let parsed = parse_cpuinfo(fixture);
        assert_eq!(parsed.logical_cpu_count, Some(2));
        assert_eq!(parsed.model_name.as_deref(), Some("BCM2711"));
    }

    #[test]
    fn cpuinfo_malformed_processor_is_reported() {
        let parsed = parse_cpuinfo("processor\t: abc\n");
        assert_eq!(parsed.logical_cpu_count, None);
        assert_eq!(parsed.parse_errors.len(), 1);
    }

    #[test]
    fn boot_id_accepts_uuid_and_rejects_garbage() {
        assert_eq!(
            parse_boot_id("492259E4-49FC-49D1-B543-76802126FF0B\n").as_deref(),
            Some("492259e4-49fc-49d1-b543-76802126ff0b")
        );
        assert_eq!(parse_boot_id("not-a-uuid"), None);
        assert_eq!(parse_boot_id("492259e4-49fc-49d1-b543-76802126ff0"), None);
    }

    #[test]
    fn btime_is_parsed_from_proc_stat() {
        let fixture = "cpu  1 2 3 4\nbtime 1700000000\ncpu0 1 2 3 4\n";
        assert_eq!(parse_btime(fixture), Some(1_700_000_000));
        assert_eq!(parse_btime("cpu 1 2 3 4\n"), None);
    }

    #[test]
    fn machine_id_fingerprint_is_stable_and_domain_separated() {
        let lower = fingerprint_from_machine_id("0123456789abcdef0123456789abcdef").unwrap();
        let upper = fingerprint_from_machine_id("0123456789ABCDEF0123456789ABCDEF\n").unwrap();
        assert_eq!(lower, upper);
        // Known answer for SHA256(b"sentinel:machine-id:v1\0" + identifier).
        assert_eq!(
            lower,
            "6f386b3c76cbd4c96de971481ff10819809f221b27218a8ec8f31d995d9d157b"
        );
    }

    #[test]
    fn machine_id_rejects_malformed_values() {
        assert_eq!(parse_machine_id(""), None);
        assert_eq!(parse_machine_id("tooshort"), None);
        assert_eq!(parse_machine_id("0123456789abcdef0123456789abcdeg"), None);
        assert_eq!(fingerprint_from_machine_id("not-a-machine-id"), None);
    }

    #[test]
    fn build_arch_maps_common_targets() {
        assert_eq!(map_build_arch("x86_64").as_deref(), Some("amd64"));
        assert_eq!(map_build_arch("aarch64").as_deref(), Some("arm64"));
    }
}
