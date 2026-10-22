//! Bounded process inventory from `/proc`.
//!
//! Each PID is described by a single read of `/proc/<pid>/stat`. The collector
//! never reads `/proc/<pid>/cmdline` or `/proc/<pid>/environ`, so no command
//! line, argument or environment data is ever collected. The reported fields
//! are exactly what the Hub inventory and `process_snapshot_entries` need:
//! `pid`, `start_ticks`, `name`, `state`.
//!
//! A PID that disappears between the directory listing and the read is normal
//! process churn and is skipped silently. When the scan stops at
//! `max_processes` the section is marked `partial`, never complete.

use serde::{Deserialize, Serialize};

use super::CollectOptions;
use super::coverage::{Coverage, CoverageBuilder};
use super::safe_io::HostFs;

/// Host-root-relative procfs root.
pub const PROC_ROOT: &str = "proc";

/// Maximum accepted length for a process name (matches the DB check).
const MAX_NAME_LEN: usize = 256;

/// Classic Linux task-state codes, classified for the Hub.
///
/// The raw single character is also kept in [`ProcessEntry::state_code`], so a
/// future kernel code is preserved even when it classifies as `Unknown`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessState {
    Running,
    Sleeping,
    DiskSleep,
    Zombie,
    Stopped,
    Tracing,
    Idle,
    Dead,
    #[default]
    Unknown,
}

impl ProcessState {
    /// Classify a `/proc/<pid>/stat` state character.
    pub fn from_code(code: char) -> Self {
        match code {
            'R' => ProcessState::Running,
            'S' => ProcessState::Sleeping,
            'D' => ProcessState::DiskSleep,
            'Z' => ProcessState::Zombie,
            'T' => ProcessState::Stopped,
            't' => ProcessState::Tracing,
            'I' => ProcessState::Idle,
            'X' | 'x' => ProcessState::Dead,
            _ => ProcessState::Unknown,
        }
    }
}

/// One process entry. Maps to the protocol `Process` fields and the
/// `process_snapshot_entries` columns `pid`, `start_ticks`, `name`, `state`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ProcessEntry {
    pub pid: i32,
    /// `starttime` from `/proc/<pid>/stat`, in clock ticks since boot.
    pub start_ticks: i64,
    /// `comm` from `/proc/<pid>/stat`, sanitised to printable text.
    pub name: String,
    /// Classified state.
    pub state: ProcessState,
    /// Raw kernel state character, preserved verbatim.
    pub state_code: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ProcessSection {
    pub coverage: Coverage,
    /// Numeric PIDs observed in `/proc` before the per-entry cap was applied.
    pub total_count: u64,
    /// Running-state entries among the scanned set (partial if `truncated`).
    pub running_count: u64,
    /// Zombie-state entries among the scanned set (partial if `truncated`).
    pub zombie_count: u64,
    /// The scan hit `max_processes`; `entries` is not the full set.
    pub truncated: bool,
    pub max_processes: usize,
    pub entries: Vec<ProcessEntry>,
    pub parse_errors: Vec<String>,
}

impl ProcessSection {
    pub fn skipped() -> Self {
        ProcessSection {
            coverage: Coverage::not_applicable("process collector disabled"),
            ..ProcessSection::default()
        }
    }
}

/// The subset of `/proc/<pid>/stat` the collector keeps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessStat {
    pub pid: i32,
    pub name: String,
    pub state: ProcessState,
    pub state_code: String,
    pub start_ticks: i64,
}

/// Parse a `/proc/<pid>/stat` line.
///
/// `comm` (field 2) can contain spaces and parentheses, so the fields are split
/// on the last `)`. After that, `state` is the first token and `starttime`
/// (field 22) is token index 19.
pub fn parse_proc_stat_line(input: &str) -> Result<ProcessStat, String> {
    let line = input.trim_end_matches(['\n', '\r']);
    let open = line.find('(').ok_or("missing '(' in comm")?;
    let close = line.rfind(')').ok_or("missing ')' in comm")?;
    if close <= open {
        return Err("malformed comm".to_string());
    }

    let pid: i32 = line[..open]
        .trim()
        .parse()
        .map_err(|_| "non-numeric pid".to_string())?;
    if pid <= 0 {
        return Err("non-positive pid".to_string());
    }

    let name = sanitize_name(&line[open + 1..close]);
    let fields: Vec<&str> = line[close + 1..].split_whitespace().collect();
    if fields.len() <= 19 {
        return Err(format!(
            "expected at least 20 fields after comm, got {}",
            fields.len()
        ));
    }

    let state_code = fields[0];
    if state_code.chars().count() != 1 {
        return Err("invalid state field".to_string());
    }
    let state_char = state_code.chars().next().expect("one char");
    let start_ticks: i64 = fields[19]
        .parse()
        .map_err(|_| "invalid starttime".to_string())?;
    if start_ticks < 0 {
        return Err("negative starttime".to_string());
    }

    Ok(ProcessStat {
        pid,
        name,
        state: ProcessState::from_code(state_char),
        state_code: state_code.to_string(),
        start_ticks,
    })
}

fn sanitize_name(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if ch.is_control() {
            out.push('?');
        } else {
            out.push(ch);
        }
    }
    let value = out.trim();
    let value = if value.is_empty() { "?" } else { value };
    truncate(value, MAX_NAME_LEN)
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

/// Read the host process table once.
pub fn collect(fs: &HostFs, options: &CollectOptions) -> ProcessSection {
    let mut builder = CoverageBuilder::new();
    builder.source(PROC_ROOT);
    let mut section = ProcessSection {
        max_processes: options.max_processes,
        ..ProcessSection::default()
    };

    let names = match fs.list_dir(PROC_ROOT) {
        Ok(names) => names,
        Err(err) if err.is_not_found() => {
            builder.missing(err.as_reason(PROC_ROOT));
            section.coverage = builder.finish();
            return section;
        }
        Err(err) => {
            builder.error(err.as_reason(PROC_ROOT));
            section.coverage = builder.finish();
            return section;
        }
    };
    builder.success();

    let mut pids: Vec<i32> = names
        .iter()
        .filter_map(|name| name.parse::<i32>().ok())
        .filter(|pid| *pid > 0)
        .collect();
    pids.sort_unstable();
    section.total_count = pids.len() as u64;

    let mut truncated = false;
    for pid in pids {
        if section.entries.len() >= options.max_processes {
            truncated = true;
            break;
        }
        let path = format!("{PROC_ROOT}/{pid}/stat");
        match fs.read_to_string(&path, Some(options.max_file_bytes)) {
            Ok(text) => match parse_proc_stat_line(&text) {
                Ok(stat) => {
                    if matches!(stat.state, ProcessState::Running) {
                        section.running_count += 1;
                    }
                    if matches!(stat.state, ProcessState::Zombie) {
                        section.zombie_count += 1;
                    }
                    section.entries.push(ProcessEntry {
                        pid: stat.pid,
                        start_ticks: stat.start_ticks,
                        name: stat.name,
                        state: stat.state,
                        state_code: stat.state_code,
                    });
                }
                Err(reason) => section.parse_errors.push(format!("{path}: {reason}")),
            },
            // The process exited between listing and reading: normal churn.
            Err(err) if err.is_not_found() => {}
            Err(err) => section.parse_errors.push(err.as_reason(&path)),
        }
    }

    for error in &section.parse_errors {
        builder.error(error);
    }
    if truncated {
        section.truncated = true;
        builder.partial(format!(
            "{PROC_ROOT}: truncated at {} processes",
            options.max_processes
        ));
    }
    section.coverage = builder.finish();
    section
}

#[cfg(test)]
mod tests {
    use super::super::coverage::CoverageStatus;
    use super::*;

    const STAT_LINE: &str =
        "1 (systemd) S 1 1 1 0 -1 4194560 100 0 0 0 10 5 0 0 20 0 1 0 12345 123456 789\n";

    fn write_stat(root: &std::path::Path, pid: i32, comm: &str, state: &str, start: u64) {
        let dir = root.join(PROC_ROOT).join(pid.to_string());
        std::fs::create_dir_all(&dir).expect("create proc dir");
        let line = format!(
            "{pid} ({comm}) {state} 1 1 1 0 -1 4194560 100 0 0 0 10 5 0 0 20 0 1 0 {start} 123456 789\n"
        );
        std::fs::write(dir.join("stat"), line).expect("write stat");
    }

    #[test]
    fn parses_state_name_and_start_ticks() {
        let stat = parse_proc_stat_line(STAT_LINE).unwrap();
        assert_eq!(stat.pid, 1);
        assert_eq!(stat.name, "systemd");
        assert_eq!(stat.state, ProcessState::Sleeping);
        assert_eq!(stat.state_code, "S");
        assert_eq!(stat.start_ticks, 12345);
    }

    #[test]
    fn comm_with_spaces_and_parentheses_is_kept() {
        let line = "42 (web (worker) [x]) R 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 999 0 0\n";
        let stat = parse_proc_stat_line(line).unwrap();
        assert_eq!(stat.pid, 42);
        assert_eq!(stat.name, "web (worker) [x]");
        assert_eq!(stat.state, ProcessState::Running);
        assert_eq!(stat.start_ticks, 999);
    }

    #[test]
    fn unknown_state_is_preserved_in_state_code() {
        let line = "7 (odd) W 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 5 0 0\n";
        let stat = parse_proc_stat_line(line).unwrap();
        assert_eq!(stat.state, ProcessState::Unknown);
        assert_eq!(stat.state_code, "W");
    }

    #[test]
    fn malformed_stat_lines_are_rejected() {
        assert!(parse_proc_stat_line("not a stat line").is_err());
        assert!(
            parse_proc_stat_line("0 (init) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 5 0 0").is_err()
        );
        assert!(parse_proc_stat_line("5 (short) S 1 1\n").is_err());
    }

    #[test]
    fn collect_reads_pid_stats_and_counts_states() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_stat(dir.path(), 1, "systemd", "S", 100);
        write_stat(dir.path(), 2, "kworker/0:1", "R", 200);
        write_stat(dir.path(), 3, "defunct", "Z", 300);
        std::fs::create_dir_all(dir.path().join(PROC_ROOT).join("notapid")).expect("extra entry");

        let fs = HostFs::new(dir.path());
        let section = collect(&fs, &CollectOptions::default());
        assert_eq!(section.total_count, 3);
        assert_eq!(section.entries.len(), 3);
        assert_eq!(section.running_count, 1);
        assert_eq!(section.zombie_count, 1);
        assert!(!section.truncated);
        assert!(section.coverage.is_usable());
        assert_eq!(section.coverage.status, CoverageStatus::Complete);
    }

    #[test]
    fn collect_marks_partial_when_truncated() {
        let dir = tempfile::tempdir().expect("tempdir");
        for pid in 1..=5 {
            write_stat(dir.path(), pid, "proc", "S", 0);
        }
        let fs = HostFs::new(dir.path());
        let options = CollectOptions {
            max_processes: 2,
            ..CollectOptions::default()
        };
        let section = collect(&fs, &options);
        assert_eq!(section.entries.len(), 2);
        assert_eq!(section.total_count, 5);
        assert!(section.truncated);
        assert_eq!(section.coverage.status, CoverageStatus::Partial);
        assert!(
            section
                .coverage
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("truncated"))
        );
    }

    #[test]
    fn missing_proc_is_missing_not_a_fallback() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fs = HostFs::new(dir.path());
        let section = collect(&fs, &CollectOptions::default());
        assert_eq!(section.coverage.status, CoverageStatus::Missing);
        assert!(section.entries.is_empty());
    }
}
