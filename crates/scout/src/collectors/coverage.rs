//! Coverage and status reporting for the read-only host collectors.
//!
//! The collectors must never turn a missing file or a parse failure into a
//! measured zero. Every section therefore carries a [`Coverage`] value and the
//! data fields are `Option`s, so "not observed" stays distinguishable from
//! "observed as zero".

use serde::{Deserialize, Serialize};

/// Outcome of attempting to read one logical collector source area.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageStatus {
    /// Every expected source was read and parsed successfully.
    Complete,
    /// Some sources or records were unavailable; the result is usable but partial.
    Partial,
    /// A source is absent on this host; nothing was observed.
    #[default]
    Missing,
    /// A source exists but could not be read or parsed.
    Error,
    /// The source does not apply to this platform.
    NotApplicable,
}

impl CoverageStatus {
    /// True only when nothing was missing or failed.
    pub fn is_complete(self) -> bool {
        matches!(self, CoverageStatus::Complete)
    }

    /// True when the section carries at least some trustworthy observations.
    pub fn is_usable(self) -> bool {
        matches!(self, CoverageStatus::Complete | CoverageStatus::Partial)
    }
}

/// Coverage metadata attached to every collector section.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Coverage {
    pub status: CoverageStatus,
    pub reason: Option<String>,
    /// Root-relative paths (or logical source names) that were consulted.
    pub sources: Vec<String>,
    /// Human-readable read/parse failures; entries here mean data is not zero.
    pub errors: Vec<String>,
}

impl Coverage {
    pub fn complete() -> Self {
        Coverage {
            status: CoverageStatus::Complete,
            ..Coverage::default()
        }
    }

    pub fn missing(reason: impl Into<String>) -> Self {
        Coverage {
            status: CoverageStatus::Missing,
            reason: Some(reason.into()),
            ..Coverage::default()
        }
    }

    pub fn partial(reason: impl Into<String>) -> Self {
        Coverage {
            status: CoverageStatus::Partial,
            reason: Some(reason.into()),
            ..Coverage::default()
        }
    }

    pub fn error(reason: impl Into<String>) -> Self {
        Coverage {
            status: CoverageStatus::Error,
            reason: Some(reason.into()),
            ..Coverage::default()
        }
    }

    pub fn not_applicable(reason: impl Into<String>) -> Self {
        Coverage {
            status: CoverageStatus::NotApplicable,
            reason: Some(reason.into()),
            ..Coverage::default()
        }
    }

    pub fn is_usable(&self) -> bool {
        self.status.is_usable()
    }

    pub fn push_source(&mut self, source: impl Into<String>) {
        self.sources.push(source.into());
    }

    pub fn push_error(&mut self, error: impl Into<String>) {
        self.errors.push(error.into());
    }

    /// Combine section coverages into one overall summary.
    pub fn aggregate<'a>(parts: impl IntoIterator<Item = &'a Coverage>) -> Coverage {
        let mut statuses: Vec<CoverageStatus> = Vec::new();
        let mut sources: Vec<String> = Vec::new();
        let mut errors: Vec<String> = Vec::new();
        let mut reason: Option<String> = None;

        for part in parts {
            statuses.push(part.status);
            for source in &part.sources {
                if !sources.contains(source) {
                    sources.push(source.clone());
                }
            }
            for error in &part.errors {
                if !errors.contains(error) {
                    errors.push(error.clone());
                }
            }
            if reason.is_none() && !matches!(part.status, CoverageStatus::Complete) {
                reason = part.reason.clone();
            }
        }

        let all = |want: CoverageStatus| statuses.iter().all(|s| *s == want);
        let any = |want: CoverageStatus| statuses.contains(&want);

        let status = if statuses.is_empty() {
            // Aggregating nothing is not a complete observation.
            CoverageStatus::NotApplicable
        } else if all(CoverageStatus::Complete) {
            CoverageStatus::Complete
        } else if any(CoverageStatus::Partial) || any(CoverageStatus::Complete) {
            CoverageStatus::Partial
        } else if any(CoverageStatus::Error) {
            CoverageStatus::Error
        } else if any(CoverageStatus::Missing) {
            CoverageStatus::Missing
        } else {
            CoverageStatus::NotApplicable
        };

        if statuses.is_empty() {
            reason = Some("no sections to aggregate".to_string());
        }

        Coverage {
            status,
            reason,
            sources,
            errors,
        }
    }
}

/// Incremental helper used while collecting a section.
#[derive(Debug, Default)]
pub struct CoverageBuilder {
    sources: Vec<String>,
    errors: Vec<String>,
    missing: Vec<String>,
    partial: Vec<String>,
    successes: u32,
    not_applicable: Vec<String>,
}

impl CoverageBuilder {
    pub fn new() -> Self {
        CoverageBuilder::default()
    }

    pub fn source(&mut self, source: impl Into<String>) {
        self.sources.push(source.into());
    }

    pub fn success(&mut self) {
        self.successes += 1;
    }

    pub fn missing(&mut self, reason: impl Into<String>) {
        self.missing.push(reason.into());
    }

    pub fn error(&mut self, reason: impl Into<String>) {
        self.errors.push(reason.into());
    }

    /// Record a non-fatal reason the result is incomplete, such as a bounded
    /// truncation. Keeps the section `Partial` without claiming a read or parse
    /// failure.
    pub fn partial(&mut self, reason: impl Into<String>) {
        self.partial.push(reason.into());
    }

    pub fn not_applicable(&mut self, reason: impl Into<String>) {
        // Kept apart from `missing`: a source that does not apply is not a
        // missing source, and `finish` must be able to report NotApplicable.
        self.not_applicable.push(reason.into());
    }

    pub fn finish(self) -> Coverage {
        let status = if self.successes > 0 {
            if self.errors.is_empty() && self.missing.is_empty() && self.partial.is_empty() {
                CoverageStatus::Complete
            } else {
                CoverageStatus::Partial
            }
        } else if !self.errors.is_empty() {
            CoverageStatus::Error
        } else if !self.missing.is_empty() {
            CoverageStatus::Missing
        } else if !self.not_applicable.is_empty() {
            CoverageStatus::NotApplicable
        } else {
            CoverageStatus::Missing
        };

        let reason = self
            .errors
            .first()
            .cloned()
            .or_else(|| self.missing.first().cloned())
            .or_else(|| self.partial.first().cloned())
            .or_else(|| self.not_applicable.first().cloned());

        Coverage {
            status,
            reason,
            sources: self.sources,
            errors: self.errors,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_reports_complete_only_when_clean() {
        let mut b = CoverageBuilder::new();
        b.source("proc/stat");
        b.success();
        let c = b.finish();
        assert_eq!(c.status, CoverageStatus::Complete);
        assert!(c.is_usable());
    }

    #[test]
    fn builder_marks_partial_with_a_missing_source() {
        let mut b = CoverageBuilder::new();
        b.source("proc/stat");
        b.source("proc/net/dev");
        b.success();
        b.missing("proc/net/dev: not found");
        let c = b.finish();
        assert_eq!(c.status, CoverageStatus::Partial);
        assert_eq!(c.reason.as_deref(), Some("proc/net/dev: not found"));
    }

    #[test]
    fn builder_marks_partial_for_bounded_truncation() {
        let mut b = CoverageBuilder::new();
        b.source("proc");
        b.success();
        b.partial("proc: truncated at 8000 processes");
        let c = b.finish();
        assert_eq!(c.status, CoverageStatus::Partial);
        assert!(c.errors.is_empty());
        assert_eq!(
            c.reason.as_deref(),
            Some("proc: truncated at 8000 processes")
        );
    }

    #[test]
    fn builder_marks_error_when_nothing_read() {
        let mut b = CoverageBuilder::new();
        b.source("var/lib/dpkg/status");
        b.error("var/lib/dpkg/status: permission denied");
        let c = b.finish();
        assert_eq!(c.status, CoverageStatus::Error);
        assert!(!c.is_usable());
    }

    #[test]
    fn builder_marks_missing_when_source_absent() {
        let mut b = CoverageBuilder::new();
        b.source("proc/stat");
        b.missing("not found");
        assert_eq!(b.finish().status, CoverageStatus::Missing);
    }

    #[test]
    fn aggregate_is_partial_when_one_section_is_partial() {
        let a = Coverage::complete();
        let b = Coverage::partial("partial");
        let combined = Coverage::aggregate([&a, &b]);
        assert_eq!(combined.status, CoverageStatus::Partial);
    }

    #[test]
    fn aggregate_is_error_when_all_parts_error() {
        let a = Coverage::error("x");
        let b = Coverage::error("y");
        assert_eq!(Coverage::aggregate([&a, &b]).status, CoverageStatus::Error);
    }

    #[test]
    fn builder_not_applicable_reaches_not_applicable() {
        let mut b = CoverageBuilder::new();
        b.source("metrics");
        b.not_applicable("metrics collector disabled");
        let c = b.finish();
        assert_eq!(c.status, CoverageStatus::NotApplicable);
        assert!(!c.is_usable());
        assert_eq!(c.reason.as_deref(), Some("metrics collector disabled"));
    }

    #[test]
    fn aggregate_of_nothing_is_not_complete() {
        let combined = Coverage::aggregate(std::iter::empty::<&Coverage>());
        assert_ne!(combined.status, CoverageStatus::Complete);
        assert_eq!(combined.status, CoverageStatus::NotApplicable);
        assert!(combined.reason.is_some());
    }
}
