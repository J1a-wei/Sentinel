//! Bounded, root-confined read-only file access for the collectors.
//!
//! All collector reads go through [`HostFs`]. A relative path is validated so
//! it cannot traverse outside the root, the file is opened, and the *open
//! descriptor* is then re-verified to still resolve inside the root before any
//! bytes are read. Reads are also capped in size.
//!
//! This is **not** a defense against an attacker who can concurrently replace
//! paths inside the host root: re-verifying the descriptor narrows the
//! time-of-check/time-of-use window but does not eliminate it. Bind the host
//! tree read-only and treat the configured root as trusted.

use std::fmt;
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::{Component, Path, PathBuf};

/// Default byte cap for the small `procfs` and `sysfs` text files.
pub const DEFAULT_MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;

/// Byte cap for the dpkg status database, which can be large on real hosts.
pub const MAX_DPKG_STATUS_BYTES: u64 = 512 * 1024 * 1024;

/// Errors returned by [`HostFs`] reads. Each variant is explicit so callers do
/// not have to guess whether a zero-length read meant "absent" or "empty".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadError {
    NotFound,
    OutsideRoot,
    NotRegularFile,
    TooLarge { limit: u64 },
    Io(String),
    NotUtf8,
}

impl ReadError {
    pub fn is_not_found(&self) -> bool {
        matches!(self, ReadError::NotFound)
    }

    pub fn as_reason(&self, source: &str) -> String {
        format!("{source}: {self}")
    }
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReadError::NotFound => write!(f, "not found"),
            ReadError::OutsideRoot => write!(f, "resolves outside the host root"),
            ReadError::NotRegularFile => write!(f, "not a regular file"),
            ReadError::TooLarge { limit } => write!(f, "exceeds size limit of {limit} bytes"),
            ReadError::Io(msg) => write!(f, "{msg}"),
            ReadError::NotUtf8 => write!(f, "not valid UTF-8"),
        }
    }
}

impl std::error::Error for ReadError {}

fn map_io(err: std::io::Error) -> ReadError {
    if err.kind() == std::io::ErrorKind::NotFound {
        ReadError::NotFound
    } else {
        ReadError::Io(err.to_string())
    }
}

/// Re-check the actual opened descriptor, not the path used to open it.
///
/// On Linux `/proc/self/fd/<fd>` names the resolved target of the descriptor,
/// so a path swapped after validation is still rejected here. A missing
/// `/proc/self/fd` is reported as an error (fail closed) rather than reading an
/// unverified file.
#[cfg(target_os = "linux")]
fn verify_open_file_confined(file: &File, canonical_root: &Path) -> Result<(), ReadError> {
    use std::os::unix::io::AsRawFd;
    let fd_path = format!("/proc/self/fd/{}", file.as_raw_fd());
    let target = fs::read_link(&fd_path)
        .map_err(|err| ReadError::Io(format!("cannot verify open file via {fd_path}: {err}")))?;
    if target.starts_with(canonical_root) {
        Ok(())
    } else {
        Err(ReadError::OutsideRoot)
    }
}

#[cfg(not(target_os = "linux"))]
fn verify_open_file_confined(_file: &File, _canonical_root: &Path) -> Result<(), ReadError> {
    // No descriptor path; the pre-open `canonicalize` check is the best
    // available approximation and cannot rule out a concurrent replacement.
    Ok(())
}

/// Root-confined reader used by every collector module.
#[derive(Debug, Clone)]
pub struct HostFs {
    root: PathBuf,
    canonical_root: Option<PathBuf>,
    default_max_bytes: u64,
}

impl HostFs {
    /// Create a reader for `root` (for example `/host` in a container).
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        let canonical_root = fs::canonicalize(&root).ok();
        HostFs {
            root,
            canonical_root,
            default_max_bytes: DEFAULT_MAX_FILE_BYTES,
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// True when the configured root could be resolved at construction time.
    pub fn root_available(&self) -> bool {
        self.canonical_root.is_some()
    }

    pub fn default_max_bytes(&self) -> u64 {
        self.default_max_bytes
    }

    /// Resolve a root-relative path without opening it, rejecting `..`,
    /// absolute paths and symlinks whose target lies outside the root.
    ///
    /// Used for existence checks and directory listing. File *content* reads go
    /// through [`HostFs::open_confined`], which re-verifies the opened
    /// descriptor instead of trusting this path.
    fn resolve(&self, rel: &str) -> Result<PathBuf, ReadError> {
        let Some(canonical_root) = self.canonical_root.as_ref() else {
            return Err(ReadError::NotFound);
        };
        let rel_path = Path::new(rel);
        if rel_path.is_absolute() {
            return Err(ReadError::OutsideRoot);
        }
        for component in rel_path.components() {
            if !matches!(component, Component::Normal(_)) {
                return Err(ReadError::OutsideRoot);
            }
        }
        let joined = self.root.join(rel_path);
        // symlink_metadata does not follow links, so a missing entry is not
        // confused with a broken link.
        fs::symlink_metadata(&joined).map_err(map_io)?;
        let canonical = fs::canonicalize(&joined).map_err(map_io)?;
        if !canonical.starts_with(canonical_root) {
            return Err(ReadError::OutsideRoot);
        }
        Ok(canonical)
    }

    /// Open a root-relative file and verify the opened descriptor still
    /// resolves inside the root. On Linux this uses `/proc/self/fd`, so a path
    /// replaced after the initial checks is still rejected before any read.
    fn open_confined(&self, rel: &str) -> Result<File, ReadError> {
        let Some(canonical_root) = self.canonical_root.as_ref() else {
            return Err(ReadError::NotFound);
        };
        let rel_path = Path::new(rel);
        if rel_path.is_absolute() {
            return Err(ReadError::OutsideRoot);
        }
        for component in rel_path.components() {
            if !matches!(component, Component::Normal(_)) {
                return Err(ReadError::OutsideRoot);
            }
        }

        let joined = self.root.join(rel_path);
        // Platforms without an fd path cannot re-verify after opening; there the
        // resolved path is checked up front (and the TOCTOU window remains).
        #[cfg(not(target_os = "linux"))]
        {
            let canonical = fs::canonicalize(&joined).map_err(map_io)?;
            if !canonical.starts_with(canonical_root) {
                return Err(ReadError::OutsideRoot);
            }
        }

        let file = File::open(&joined).map_err(map_io)?;
        verify_open_file_confined(&file, canonical_root)?;
        Ok(file)
    }

    /// Read a small file to a UTF-8 string, capped at `max_bytes`.
    pub fn read_to_string(&self, rel: &str, max_bytes: Option<u64>) -> Result<String, ReadError> {
        let max = max_bytes.unwrap_or(self.default_max_bytes);
        let file = self.open_confined(rel)?;
        let meta = file.metadata().map_err(map_io)?;
        if !meta.is_file() {
            return Err(ReadError::NotRegularFile);
        }
        if meta.len() > max {
            return Err(ReadError::TooLarge { limit: max });
        }
        let mut limited = file.take(max.saturating_add(1));
        let mut bytes = Vec::new();
        limited.read_to_end(&mut bytes).map_err(map_io)?;
        if bytes.len() as u64 > max {
            return Err(ReadError::TooLarge { limit: max });
        }
        String::from_utf8(bytes).map_err(|_| ReadError::NotUtf8)
    }

    /// Open a file for streaming reads with an upfront size cap.
    ///
    /// `procfs` reports a zero length, so the cap is also enforced by the
    /// caller while streaming.
    pub fn open_reader(&self, rel: &str, max_bytes: u64) -> Result<BufReader<File>, ReadError> {
        let file = self.open_confined(rel)?;
        let meta = file.metadata().map_err(map_io)?;
        if !meta.is_file() {
            return Err(ReadError::NotRegularFile);
        }
        if meta.len() > max_bytes {
            return Err(ReadError::TooLarge { limit: max_bytes });
        }
        Ok(BufReader::new(file))
    }

    /// List the entry names of a directory (not following symlinks).
    pub fn list_dir(&self, rel: &str) -> Result<Vec<String>, ReadError> {
        let path = self.resolve(rel)?;
        let meta = fs::metadata(&path).map_err(map_io)?;
        if !meta.is_dir() {
            return Err(ReadError::NotRegularFile);
        }
        let mut names = Vec::new();
        for entry in fs::read_dir(&path).map_err(map_io)? {
            let entry = entry.map_err(map_io)?;
            if let Some(name) = entry.file_name().to_str() {
                names.push(name.to_string());
            }
        }
        names.sort();
        Ok(names)
    }

    /// True when a root-relative entry exists and stays inside the root.
    pub fn entry_exists(&self, rel: &str) -> bool {
        self.resolve(rel).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::atomic::{AtomicU32, Ordering};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    struct TempTree {
        root: PathBuf,
    }

    impl TempTree {
        fn new() -> Self {
            let unique = format!(
                "sentinel-collectors-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::SeqCst)
            );
            let root = std::env::temp_dir().join(unique);
            fs::create_dir_all(&root).expect("create temp root");
            TempTree { root }
        }

        fn write(&self, rel: &str, contents: &str) {
            let path = self.root.join(rel);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("create parent");
            }
            let mut file = File::create(path).expect("create file");
            file.write_all(contents.as_bytes()).expect("write file");
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn reads_a_file_inside_the_root() {
        let tree = TempTree::new();
        tree.write("etc/os-release", "ID=ubuntu\n");
        let host = HostFs::new(&tree.root);
        let text = host.read_to_string("etc/os-release", None).unwrap();
        assert_eq!(text, "ID=ubuntu\n");
    }

    #[test]
    fn missing_file_is_not_found() {
        let tree = TempTree::new();
        let host = HostFs::new(&tree.root);
        assert_eq!(
            host.read_to_string("etc/nope", None).unwrap_err(),
            ReadError::NotFound
        );
    }

    #[test]
    fn missing_root_reports_not_found() {
        let host = HostFs::new(std::env::temp_dir().join("sentinel-does-not-exist-xyz"));
        assert!(!host.root_available());
        assert_eq!(
            host.read_to_string("etc/os-release", None).unwrap_err(),
            ReadError::NotFound
        );
    }

    #[test]
    fn rejects_parent_traversal() {
        let tree = TempTree::new();
        let host = HostFs::new(&tree.root);
        assert_eq!(
            host.read_to_string("../etc/passwd", None).unwrap_err(),
            ReadError::OutsideRoot
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_escaping_the_root() {
        let tree = TempTree::new();
        // A file outside the root that must not be readable through a link.
        let outside = tree.root.with_extension("outside");
        fs::write(&outside, "secret\n").expect("write outside file");
        std::os::unix::fs::symlink(&outside, tree.root.join("escape")).expect("create symlink");

        let host = HostFs::new(&tree.root);
        assert_eq!(
            host.read_to_string("escape", None).unwrap_err(),
            ReadError::OutsideRoot
        );
        let _ = fs::remove_file(outside);
    }

    #[cfg(unix)]
    #[test]
    fn allows_symlink_that_stays_inside_the_root() {
        // Mirrors /etc/os-release -> ../usr/lib/os-release on a real host.
        let tree = TempTree::new();
        tree.write("usr/lib/os-release", "ID=ubuntu\n");
        fs::create_dir_all(tree.root.join("etc")).expect("create etc");
        std::os::unix::fs::symlink("../usr/lib/os-release", tree.root.join("etc/os-release"))
            .expect("create symlink");

        let host = HostFs::new(&tree.root);
        let text = host.read_to_string("etc/os-release", None).unwrap();
        assert_eq!(text, "ID=ubuntu\n");
    }

    #[test]
    fn enforces_size_limit() {
        let tree = TempTree::new();
        tree.write("big", "0123456789");
        let host = HostFs::new(&tree.root);
        assert_eq!(
            host.read_to_string("big", Some(4)).unwrap_err(),
            ReadError::TooLarge { limit: 4 }
        );
    }
}
