//! TCP listen and UDP bind endpoints from the host socket tables.
//!
//! Sources are `/proc/net/tcp`, `tcp6`, `udp` and `udp6` under the configured
//! network prefix. TCP entries are kept only in the `LISTEN` state; UDP entries
//! are reported as *bindings* (never as listeners) and connected UDP sockets are
//! excluded so client sockets are not mistaken for services.
//!
//! Address bytes in these files are little-endian per 32-bit word, so the hex is
//! converted accordingly. Loopback is `127.0.0.0/8` and `::1` (including
//! IPv4-mapped forms); wildcard addresses are explicitly *not* loopback.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

use super::CollectOptions;
use super::coverage::{Coverage, CoverageBuilder};
use super::safe_io::HostFs;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortProtocol {
    #[default]
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpFamily {
    #[default]
    V4,
    V6,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PortEndpoint {
    pub protocol: PortProtocol,
    pub family: IpFamily,
    /// Canonical textual form, without brackets (for example `::1`).
    pub address: String,
    pub port: u16,
    pub is_loopback: bool,
    pub is_unspecified: bool,
    /// Raw state hex from the socket table (`0A` = TCP LISTEN).
    pub state_raw: String,
    pub uid: Option<u32>,
    pub socket_inode: Option<u64>,
    /// Root-relative source path this endpoint was read from.
    pub source: String,
}

impl Default for PortEndpoint {
    fn default() -> Self {
        PortEndpoint {
            protocol: PortProtocol::Tcp,
            family: IpFamily::V4,
            address: String::new(),
            port: 0,
            is_loopback: false,
            is_unspecified: false,
            state_raw: String::new(),
            uid: None,
            socket_inode: None,
            source: String::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PortFileCoverage {
    pub path: String,
    pub protocol: PortProtocol,
    pub family: IpFamily,
    pub coverage: Coverage,
    pub entries_seen: u64,
    pub entries_kept: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PortsSection {
    pub coverage: Coverage,
    pub endpoints: Vec<PortEndpoint>,
    pub tcp_listen_count: u64,
    pub udp_bind_count: u64,
    pub loopback_count: u64,
    pub unspecified_count: u64,
    pub sources: Vec<PortFileCoverage>,
    pub parse_errors: Vec<String>,
}

impl PortsSection {
    pub fn skipped() -> Self {
        PortsSection {
            coverage: Coverage::not_applicable("port collector disabled"),
            ..PortsSection::default()
        }
    }

    /// Endpoints that are not loopback (the external binding set).
    pub fn non_loopback(&self) -> impl Iterator<Item = &PortEndpoint> {
        self.endpoints
            .iter()
            .filter(|endpoint| !endpoint.is_loopback)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ParsedPortFile {
    pub endpoints: Vec<PortEndpoint>,
    pub entries_seen: u64,
    pub entries_skipped: u64,
    pub parse_errors: Vec<String>,
}

/// Parse one `/proc/net/{tcp,tcp6,udp,udp6}` file.
pub fn parse_proc_net(
    input: &str,
    protocol: PortProtocol,
    family: IpFamily,
    source: &str,
) -> ParsedPortFile {
    let mut out = ParsedPortFile::default();
    for (index, raw) in input.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        // Header lines do not start with a numbered slot such as `0:`.
        let Some(slot) = fields.first() else {
            continue;
        };
        if !slot.ends_with(':') {
            continue;
        }
        if fields.len() < 4 {
            out.parse_errors
                .push(format!("line {}: too few fields", index + 1));
            continue;
        }
        out.entries_seen += 1;

        let local = fields[1];
        let remote = fields[2];
        let state = fields[3];
        let uid = fields.get(7).and_then(|value| value.parse::<u32>().ok());
        let inode = fields.get(9).and_then(|value| value.parse::<u64>().ok());

        match parse_endpoint(protocol, family, local, remote, state, uid, inode, source) {
            Ok(Some(endpoint)) => out.endpoints.push(endpoint),
            Ok(None) => out.entries_skipped += 1,
            Err(reason) => out
                .parse_errors
                .push(format!("line {}: {reason}", index + 1)),
        }
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn parse_endpoint(
    protocol: PortProtocol,
    family: IpFamily,
    local: &str,
    remote: &str,
    state: &str,
    uid: Option<u32>,
    inode: Option<u64>,
    source: &str,
) -> Result<Option<PortEndpoint>, String> {
    // State handling differs per protocol; "-" is used to skip a record.
    let keep = if matches!(protocol, PortProtocol::Tcp) {
        state.eq_ignore_ascii_case("0A")
    } else {
        // A bound, unconnected UDP socket has no remote port.
        remote_port_hex(remote)
            .map(|port| port == 0)
            .unwrap_or(false)
    };
    if !keep {
        return Ok(None);
    }

    let (address_hex, port_hex) = local
        .split_once(':')
        .ok_or_else(|| format!("invalid local address '{local}'"))?;
    let port = parse_hex_u16(port_hex)?;
    if port == 0 {
        return Ok(None);
    }
    let address = parse_address(address_hex, family)?;
    let is_loopback = ip_is_loopback(&address);
    let is_unspecified = match &address {
        IpAddr::V4(value) => value.is_unspecified(),
        IpAddr::V6(value) => value.is_unspecified(),
    };

    Ok(Some(PortEndpoint {
        protocol,
        family,
        address: address.to_string(),
        port,
        is_loopback,
        is_unspecified,
        state_raw: state.to_ascii_uppercase(),
        uid,
        socket_inode: inode,
        source: source.to_string(),
    }))
}

fn remote_port_hex(remote: &str) -> Option<u16> {
    let (_, port_hex) = remote.split_once(':')?;
    u16::from_str_radix(port_hex, 16).ok()
}

fn parse_hex_u16(value: &str) -> Result<u16, String> {
    u16::from_str_radix(value, 16).map_err(|_| format!("invalid port '{value}'"))
}

/// Convert the little-endian hex words used by procfs into an IP address.
fn parse_address(hex: &str, family: IpFamily) -> Result<IpAddr, String> {
    match family {
        IpFamily::V4 => {
            if hex.len() != 8 {
                return Err(format!("invalid IPv4 address '{hex}'"));
            }
            let word = u32::from_str_radix(hex, 16)
                .map_err(|_| format!("invalid IPv4 address '{hex}'"))?;
            Ok(IpAddr::V4(Ipv4Addr::from(word.to_le_bytes())))
        }
        IpFamily::V6 => {
            if hex.len() != 32 {
                return Err(format!("invalid IPv6 address '{hex}'"));
            }
            let mut bytes = [0u8; 16];
            for word_index in 0..4 {
                let start = word_index * 8;
                let word = u32::from_str_radix(&hex[start..start + 8], 16)
                    .map_err(|_| format!("invalid IPv6 address '{hex}'"))?;
                bytes[word_index * 4..word_index * 4 + 4].copy_from_slice(&word.to_le_bytes());
            }
            Ok(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
    }
}

fn ip_is_loopback(address: &IpAddr) -> bool {
    match address {
        IpAddr::V4(value) => value.octets()[0] == 127,
        IpAddr::V6(value) => {
            if value.is_loopback() {
                return true;
            }
            match value.to_ipv4_mapped() {
                Some(mapped) => mapped.octets()[0] == 127,
                None => false,
            }
        }
    }
}

const PROTOCOL_FILES: [(&str, PortProtocol, IpFamily); 4] = [
    ("tcp", PortProtocol::Tcp, IpFamily::V4),
    ("tcp6", PortProtocol::Tcp, IpFamily::V6),
    ("udp", PortProtocol::Udp, IpFamily::V4),
    ("udp6", PortProtocol::Udp, IpFamily::V6),
];

/// Read all four socket tables once.
pub fn collect(fs: &HostFs, options: &CollectOptions) -> PortsSection {
    let prefix = options.network_proc_prefix.trim_end_matches('/');
    let mut section = PortsSection::default();
    let mut file_coverages: Vec<Coverage> = Vec::with_capacity(PROTOCOL_FILES.len());

    for (name, protocol, family) in PROTOCOL_FILES {
        let path = format!("{prefix}/{name}");
        let mut builder = CoverageBuilder::new();
        builder.source(&path);
        let mut file = PortFileCoverage {
            path: path.clone(),
            protocol,
            family,
            ..PortFileCoverage::default()
        };

        match fs.read_to_string(&path, Some(options.max_file_bytes)) {
            Ok(text) => {
                let parsed = parse_proc_net(&text, protocol, family, &path);
                for error in &parsed.parse_errors {
                    builder.error(format!("{path}: {error}"));
                    section.parse_errors.push(format!("{path}: {error}"));
                }
                file.entries_seen = parsed.entries_seen;
                file.entries_kept = parsed.endpoints.len() as u64;
                section.endpoints.extend(parsed.endpoints);
                builder.success();
            }
            Err(err) if err.is_not_found() => {
                builder.missing(err.as_reason(&path));
                section.parse_errors.push(err.as_reason(&path));
            }
            Err(err) => {
                builder.error(err.as_reason(&path));
                section.parse_errors.push(err.as_reason(&path));
            }
        }
        file.coverage = builder.finish();
        file_coverages.push(file.coverage.clone());
        section.sources.push(file);
    }

    section.tcp_listen_count = section
        .endpoints
        .iter()
        .filter(|endpoint| matches!(endpoint.protocol, PortProtocol::Tcp))
        .count() as u64;
    section.udp_bind_count = section
        .endpoints
        .iter()
        .filter(|endpoint| matches!(endpoint.protocol, PortProtocol::Udp))
        .count() as u64;
    section.loopback_count = section
        .endpoints
        .iter()
        .filter(|endpoint| endpoint.is_loopback)
        .count() as u64;
    section.unspecified_count = section
        .endpoints
        .iter()
        .filter(|endpoint| endpoint.is_unspecified)
        .count() as u64;

    if !options.include_loopback {
        section.endpoints.retain(|endpoint| !endpoint.is_loopback);
    }

    section.coverage = Coverage::aggregate(file_coverages.iter());
    section
}

#[cfg(test)]
mod tests {
    use super::*;

    const TCP_V4: &str = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0
   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 67890 1 0000000000000000 100 0 0 10 0
   2: 3500007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   101        0 513839 1 0000000000000000 100 0 0 10 0
   3: 0100007F:1F91 0100007F:1234 01 00000000:00000000 00:00000000 00000000  1000        0 11111 1 0000000000000000 100 0 0 10 0
";

    const TCP_V6: &str = "\
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 9299 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000001000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 9300 1 0000000000000000 100 0 0 10 0
   2: B80D0120000000000000000001000000:01BB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 538986 2 0000000000000000 100 0 0 10 0
";

    const UDP_V4: &str = "\
   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
   0: 3500007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   101        0 513838 2 0000000000000000 0
   1: 00000000:A2A9 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 525594 2 0000000000000000 0
   2: 00000000:1234 0100007F:1F90 07 00000000:00000000 00:00000000 00000000     0        0 1 2 0000000000000000 0
";

    #[test]
    fn tcp_keeps_only_listen_and_decodes_little_endian() {
        let parsed = parse_proc_net(TCP_V4, PortProtocol::Tcp, IpFamily::V4, "proc/net/tcp");
        assert_eq!(parsed.entries_seen, 4);
        assert_eq!(parsed.endpoints.len(), 3);
        assert_eq!(parsed.entries_skipped, 1);

        let first = &parsed.endpoints[0];
        assert_eq!(first.address, "127.0.0.1");
        assert_eq!(first.port, 8080);
        assert!(first.is_loopback);
        assert!(!first.is_unspecified);
        assert_eq!(first.uid, Some(1000));
        assert_eq!(first.socket_inode, Some(12345));

        let wildcard = parsed
            .endpoints
            .iter()
            .find(|endpoint| endpoint.port == 22)
            .unwrap();
        assert_eq!(wildcard.address, "0.0.0.0");
        assert!(wildcard.is_unspecified);
        assert!(!wildcard.is_loopback);
    }

    #[test]
    fn loopback_covers_whole_127_slash_8() {
        let parsed = parse_proc_net(TCP_V4, PortProtocol::Tcp, IpFamily::V4, "proc/net/tcp");
        let resolved = parsed
            .endpoints
            .iter()
            .find(|endpoint| endpoint.port == 53)
            .unwrap();
        assert_eq!(resolved.address, "127.0.0.53");
        assert!(resolved.is_loopback);
    }

    #[test]
    fn tcp6_decodes_and_filters_loopback() {
        let parsed = parse_proc_net(TCP_V6, PortProtocol::Tcp, IpFamily::V6, "proc/net/tcp6");
        assert_eq!(parsed.endpoints.len(), 3);
        let wildcard = parsed
            .endpoints
            .iter()
            .find(|endpoint| endpoint.port == 22)
            .unwrap();
        assert_eq!(wildcard.address, "::");
        assert!(wildcard.is_unspecified);
        assert!(!wildcard.is_loopback);

        let loopback = parsed
            .endpoints
            .iter()
            .find(|endpoint| endpoint.port == 8080)
            .unwrap();
        assert_eq!(loopback.address, "::1");
        assert!(loopback.is_loopback);

        let global = parsed
            .endpoints
            .iter()
            .find(|endpoint| endpoint.port == 443)
            .unwrap();
        assert_eq!(global.address, "2001:db8::1");
        assert!(!global.is_loopback);
    }

    #[test]
    fn udp_is_bind_not_listen_and_skips_connected() {
        let parsed = parse_proc_net(UDP_V4, PortProtocol::Udp, IpFamily::V4, "proc/net/udp");
        assert_eq!(parsed.entries_seen, 3);
        assert_eq!(parsed.endpoints.len(), 2);
        for endpoint in &parsed.endpoints {
            assert_eq!(endpoint.protocol, PortProtocol::Udp);
        }
        assert!(
            parsed
                .endpoints
                .iter()
                .all(|endpoint| endpoint.port != 0x1234)
        );
    }

    #[test]
    fn malformed_address_is_reported_not_zero() {
        let fixture = "   0: ZZZZZZZZ:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000 0 1\n";
        let parsed = parse_proc_net(fixture, PortProtocol::Tcp, IpFamily::V4, "proc/net/tcp");
        assert!(parsed.endpoints.is_empty());
        assert_eq!(parsed.parse_errors.len(), 1);
    }

    #[test]
    fn ipv4_mapped_loopback_is_detected() {
        // ::ffff:127.0.0.1 -> words: 00000000 00000000 FFFF0000 0100007F
        let parsed = parse_proc_net(
            "   0: 0000000000000000FFFF00000100007F:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1\n",
            PortProtocol::Tcp,
            IpFamily::V6,
            "proc/net/tcp6",
        );
        assert_eq!(parsed.endpoints.len(), 1);
        assert!(parsed.endpoints[0].is_loopback);
        assert_eq!(parsed.endpoints[0].address, "::ffff:127.0.0.1");
    }

    #[test]
    fn non_loopback_iterator_excludes_loopback() {
        let section = PortsSection {
            endpoints: vec![
                PortEndpoint {
                    address: "127.0.0.1".to_string(),
                    is_loopback: true,
                    ..PortEndpoint::default()
                },
                PortEndpoint {
                    address: "0.0.0.0".to_string(),
                    ..PortEndpoint::default()
                },
            ],
            ..PortsSection::default()
        };
        let external: Vec<&PortEndpoint> = section.non_loopback().collect();
        assert_eq!(external.len(), 1);
        assert_eq!(external[0].address, "0.0.0.0");
    }
}
