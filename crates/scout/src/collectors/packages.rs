//! Installed-package inventory from the host dpkg database.
//!
//! Only `Status: ... ok installed` records are kept. The full Debian version
//! string (epoch, revision) is preserved verbatim; the source package name and
//! version are retained when the `Source` field provides them. Package origin
//! (Ubuntu vs third party) cannot be established from the status database
//! alone, so every entry is reported as `unknown` with an explicit evidence
//! note rather than being assumed safe.

use std::io::BufRead;

use serde::{Deserialize, Serialize};

use super::CollectOptions;
use super::coverage::{Coverage, CoverageBuilder};
use super::safe_io::{HostFs, ReadError};

/// Dpkg status path relative to the host root.
pub const DPKG_STATUS_PATH: &str = "var/lib/dpkg/status";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OriginStatus {
    Ubuntu,
    ThirdParty,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PackageEntry {
    pub name: String,
    pub version: String,
    pub architecture: String,
    pub source_name: Option<String>,
    pub source_version: Option<String>,
    pub origin_status: OriginStatus,
    pub origin_evidence: Option<String>,
}

impl Default for PackageEntry {
    fn default() -> Self {
        PackageEntry {
            name: String::new(),
            version: String::new(),
            architecture: String::new(),
            source_name: None,
            source_version: None,
            origin_status: OriginStatus::Unknown,
            origin_evidence: None,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DpkgStatusParse {
    pub entries: Vec<PackageEntry>,
    /// Records (paragraphs) with any content that were examined.
    pub inspected_records: u64,
    pub installed_records: u64,
    /// Records that were not in the installed state or were malformed.
    pub skipped_records: u64,
    pub parse_errors: Vec<String>,
    pub truncated: bool,
    pub bytes_read: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PackagesSection {
    pub coverage: Coverage,
    pub source: Option<String>,
    pub entries: Vec<PackageEntry>,
    pub inspected_records: u64,
    pub installed_records: u64,
    pub skipped_records: u64,
    pub truncated: bool,
    pub bytes_read: u64,
    pub parse_errors: Vec<String>,
}

impl PackagesSection {
    pub fn skipped() -> Self {
        PackagesSection {
            coverage: Coverage::not_applicable("package collector disabled"),
            source: None,
            ..PackagesSection::default()
        }
    }
}

#[derive(Debug, Default)]
struct Paragraph {
    package: Option<String>,
    status: Option<String>,
    architecture: Option<String>,
    version: Option<String>,
    source: Option<String>,
}

impl Paragraph {
    fn is_empty(&self) -> bool {
        self.package.is_none()
            && self.status.is_none()
            && self.architecture.is_none()
            && self.version.is_none()
            && self.source.is_none()
    }
}

#[derive(Debug, Default)]
struct DpkgParser {
    current: Paragraph,
    result: DpkgStatusParse,
}

impl DpkgParser {
    fn push_line(&mut self, line: &str) {
        let line = line.trim_end_matches(['\n', '\r']);
        if line.is_empty() {
            self.flush();
            return;
        }
        // Indented lines are continuation of the previous field (typically
        // Description); none of the fields we keep use continuations.
        if line.starts_with(' ') || line.starts_with('\t') {
            return;
        }
        let Some((key, value)) = line.split_once(':') else {
            // Never echo the raw line: it could carry host data, and this reason
            // is forwarded to coverage.
            self.result
                .parse_errors
                .push("malformed line without ':'".to_string());
            return;
        };
        let value = value.trim().to_string();
        match key {
            "Package" => self.current.package = Some(value),
            "Status" => self.current.status = Some(value),
            "Architecture" => self.current.architecture = Some(value),
            "Version" => self.current.version = Some(value),
            "Source" => self.current.source = Some(value),
            _ => {}
        }
    }

    fn flush(&mut self) {
        let paragraph = std::mem::take(&mut self.current);
        if paragraph.is_empty() {
            return;
        }
        self.result.inspected_records += 1;

        let Some(package) = paragraph.package else {
            self.result.skipped_records += 1;
            self.result
                .parse_errors
                .push("record without Package field".to_string());
            return;
        };

        let installed = paragraph
            .status
            .as_deref()
            .map(is_installed_status)
            .unwrap_or(false);
        if !installed {
            self.result.skipped_records += 1;
            return;
        }

        let (Some(version), Some(architecture)) = (paragraph.version, paragraph.architecture)
        else {
            self.result.skipped_records += 1;
            self.result.parse_errors.push(format!(
                "{package}: installed record missing Version or Architecture"
            ));
            return;
        };

        let (source_name, source_version) = match paragraph.source {
            Some(source) => parse_source(&source, &version),
            // Debian convention: without a Source field the source package is
            // the binary package and shares its version.
            None => (Some(package.clone()), Some(version.clone())),
        };

        self.result.entries.push(PackageEntry {
            name: package,
            version,
            architecture,
            source_name,
            source_version,
            origin_status: OriginStatus::Unknown,
            origin_evidence: Some("dpkg_status_only".to_string()),
        });
        self.result.installed_records += 1;
    }
}

fn is_installed_status(status: &str) -> bool {
    let mut parts = status.split_whitespace();
    let _action = parts.next();
    let ok = parts.next();
    let state = parts.next();
    matches!(ok, Some("ok")) && matches!(state, Some("installed"))
}

fn parse_source(source: &str, binary_version: &str) -> (Option<String>, Option<String>) {
    let source = source.trim();
    if source.is_empty() {
        return (None, None);
    }
    if let Some(open) = source.find('(') {
        let name = source[..open].trim();
        if name.is_empty() {
            return (None, None);
        }
        if let Some(relative_close) = source[open..].find(')') {
            let version = source[open + 1..open + relative_close].trim();
            let version = if version.is_empty() {
                binary_version.to_string()
            } else {
                version.to_string()
            };
            return (Some(name.to_string()), Some(version));
        }
        return (Some(name.to_string()), Some(binary_version.to_string()));
    }
    (Some(source.to_string()), Some(binary_version.to_string()))
}

/// Parse a complete dpkg status document (primarily for tests).
pub fn parse_dpkg_status(input: &str) -> DpkgStatusParse {
    let mut parser = DpkgParser::default();
    for line in input.lines() {
        parser.push_line(line);
    }
    parser.flush();
    parser.result.bytes_read = input.len() as u64;
    parser.result
}

/// Stream-parse a dpkg status document, stopping at `max_bytes`.
///
/// A trailing incomplete paragraph at the truncation point is dropped rather
/// than emitted as a partial record, and `truncated` is set.
pub fn parse_dpkg_status_reader<R: BufRead>(
    reader: R,
    max_bytes: u64,
) -> Result<DpkgStatusParse, ReadError> {
    let mut parser = DpkgParser::default();
    // `Take` implements `BufRead` and reports EOF at the limit, so a single
    // pathological line can never make `read_line` allocate more than
    // `max_bytes + 1` bytes. Without this the cap would apply only after the
    // line had already been buffered in full.
    let mut limited = reader.take(max_bytes.saturating_add(1));
    let mut bytes_read: u64 = 0;
    let mut line = String::new();
    loop {
        line.clear();
        let read = limited
            .read_line(&mut line)
            .map_err(|err| ReadError::Io(err.to_string()))?;
        if read == 0 {
            break;
        }
        bytes_read += read as u64;
        if bytes_read > max_bytes {
            // Cap reached: the document is incomplete. Drop the trailing
            // (possibly partial) paragraph rather than emit it as a record.
            parser.result.truncated = true;
            parser.result.bytes_read = bytes_read;
            return Ok(parser.result);
        }
        parser.push_line(&line);
    }
    parser.flush();
    parser.result.bytes_read = bytes_read;
    Ok(parser.result)
}

/// Read the host's installed package database once.
pub fn collect(fs: &HostFs, options: &CollectOptions) -> PackagesSection {
    let mut builder = CoverageBuilder::new();
    builder.source(DPKG_STATUS_PATH);
    let mut section = PackagesSection {
        source: Some(DPKG_STATUS_PATH.to_string()),
        ..PackagesSection::default()
    };

    match fs.open_reader(DPKG_STATUS_PATH, options.max_dpkg_status_bytes) {
        Ok(reader) => match parse_dpkg_status_reader(reader, options.max_dpkg_status_bytes) {
            Ok(parsed) => {
                for error in &parsed.parse_errors {
                    builder.error(format!("{DPKG_STATUS_PATH}: {error}"));
                }
                if parsed.truncated {
                    builder.partial(format!(
                        "{DPKG_STATUS_PATH}: truncated at {} bytes",
                        options.max_dpkg_status_bytes
                    ));
                }
                section.entries = parsed.entries;
                section.inspected_records = parsed.inspected_records;
                section.installed_records = parsed.installed_records;
                section.skipped_records = parsed.skipped_records;
                section.truncated = parsed.truncated;
                section.bytes_read = parsed.bytes_read;
                section.parse_errors = parsed.parse_errors;
                builder.success();
            }
            Err(err) => builder.error(err.as_reason(DPKG_STATUS_PATH)),
        },
        Err(err) if err.is_not_found() => builder.missing(err.as_reason(DPKG_STATUS_PATH)),
        Err(err) => builder.error(err.as_reason(DPKG_STATUS_PATH)),
    }

    section.coverage = builder.finish();
    section
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufReader, Cursor, Read};

    // Fictional dpkg status with Ubuntu 22.04 and 24.04-style package versions.
    const STATUS: &str = "\
Package: adduser
Status: install ok installed
Priority: important
Architecture: all
Version: 3.118ubuntu5

Package: apt
Status: install ok installed
Architecture: amd64
Version: 2.4.11
Source: apt (2.4.11)

Package: bash
Status: deinstall ok config-files
Architecture: amd64
Version: 5.1-6ubuntu1

Package: binutils
Status: install ok installed
Architecture: amd64
Version: 2.38-4ubuntu2.6
Source: binutils
Description: GNU assembler, linker and binary utilities
 A longer description continuation line
 that must be ignored.

Package: held-tool
Status: hold ok installed
Architecture: amd64
Version: 1:2.3-4ubuntu5
Source: held-source (1:2.3-4ubuntu5)

Package: broken-installed
Status: install ok installed
Architecture: amd64
";

    #[test]
    fn keeps_only_installed_records() {
        let parsed = parse_dpkg_status(STATUS);
        let names: Vec<&str> = parsed.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["adduser", "apt", "binutils", "held-tool"]);
        assert_eq!(parsed.inspected_records, 6);
        assert_eq!(parsed.installed_records, 4);
        // bash (config-files) and broken-installed (missing Version) are skipped.
        assert_eq!(parsed.skipped_records, 2);
        assert_eq!(parsed.parse_errors.len(), 1);
    }

    #[test]
    fn preserves_full_version_and_architecture() {
        let parsed = parse_dpkg_status(STATUS);
        let apt = parsed.entries.iter().find(|e| e.name == "apt").unwrap();
        assert_eq!(apt.version, "2.4.11");
        assert_eq!(apt.architecture, "amd64");
        assert_eq!(apt.source_name.as_deref(), Some("apt"));
        assert_eq!(apt.source_version.as_deref(), Some("2.4.11"));

        let held = parsed
            .entries
            .iter()
            .find(|e| e.name == "held-tool")
            .unwrap();
        assert_eq!(held.version, "1:2.3-4ubuntu5");
        assert_eq!(held.source_name.as_deref(), Some("held-source"));
        assert_eq!(held.source_version.as_deref(), Some("1:2.3-4ubuntu5"));
    }

    #[test]
    fn missing_source_falls_back_to_binary_package() {
        let parsed = parse_dpkg_status(STATUS);
        let adduser = parsed.entries.iter().find(|e| e.name == "adduser").unwrap();
        assert_eq!(adduser.source_name.as_deref(), Some("adduser"));
        assert_eq!(adduser.source_version.as_deref(), Some("3.118ubuntu5"));
    }

    #[test]
    fn source_without_version_uses_binary_version() {
        let parsed = parse_dpkg_status(STATUS);
        let binutils = parsed
            .entries
            .iter()
            .find(|e| e.name == "binutils")
            .unwrap();
        assert_eq!(binutils.source_name.as_deref(), Some("binutils"));
        assert_eq!(binutils.source_version.as_deref(), Some("2.38-4ubuntu2.6"));
    }

    #[test]
    fn origin_is_unknown_not_assumed_safe() {
        let parsed = parse_dpkg_status(STATUS);
        for entry in &parsed.entries {
            assert_eq!(entry.origin_status, OriginStatus::Unknown);
            assert_eq!(entry.origin_evidence.as_deref(), Some("dpkg_status_only"));
        }
    }

    #[test]
    fn empty_input_yields_no_entries() {
        let parsed = parse_dpkg_status("");
        assert!(parsed.entries.is_empty());
        assert_eq!(parsed.inspected_records, 0);
    }

    #[test]
    fn streaming_truncates_at_limit_without_partial_record() {
        let cursor = Cursor::new(STATUS.as_bytes());
        let reader = BufReader::new(cursor);
        let parsed = parse_dpkg_status_reader(reader, 120).unwrap();
        assert!(parsed.truncated);
        // Only paragraphs completed before the cap are present.
        assert!(parsed.entries.iter().all(|e| e.name != "broken-installed"));
        assert!(parsed.bytes_read > 120);
    }

    #[test]
    fn streaming_reads_full_document_without_truncation() {
        let cursor = Cursor::new(STATUS.as_bytes());
        let reader = BufReader::new(cursor);
        let parsed = parse_dpkg_status_reader(reader, 1024 * 1024).unwrap();
        assert!(!parsed.truncated);
        assert_eq!(parsed.installed_records, 4);
    }

    #[test]
    fn streaming_bounds_a_single_long_line() {
        struct Repeats {
            remaining: usize,
        }
        impl Read for Repeats {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.remaining == 0 || buf.is_empty() {
                    return Ok(0);
                }
                let count = buf.len().min(self.remaining);
                for byte in &mut buf[..count] {
                    *byte = b'x';
                }
                self.remaining -= count;
                Ok(count)
            }
        }

        let reader = BufReader::with_capacity(
            16,
            Repeats {
                remaining: 1_000_000,
            },
        );
        let parsed = parse_dpkg_status_reader(reader, 1024).unwrap();
        assert!(parsed.truncated);
        // The cap is enforced while reading, not after buffering the whole line.
        assert!(parsed.bytes_read <= 1025, "read {}", parsed.bytes_read);
        assert!(parsed.entries.is_empty());
    }
}
