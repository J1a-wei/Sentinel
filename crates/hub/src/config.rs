use anyhow::{Context, Result, ensure};
use sentinel_protocol::secret;
use std::{env, net::SocketAddr, path::PathBuf};

pub struct Config {
    pub database_url: String,
    pub admin_token: String,
    pub bind: SocketAddr,
    pub nats_url: String,
    pub nats_token: Option<String>,
    pub web_dir: PathBuf,
}
impl Config {
    pub fn load() -> Result<Self> {
        let admin_token = secret("SENTINEL_ADMIN_TOKEN")?
            .context("SENTINEL_ADMIN_TOKEN or SENTINEL_ADMIN_TOKEN_FILE is required")?;
        ensure!(
            admin_token.len() >= 32,
            "administrator credential must be at least 32 characters"
        );
        Ok(Self {
            database_url: secret("SENTINEL_DATABASE_URL")?
                .context("SENTINEL_DATABASE_URL or SENTINEL_DATABASE_URL_FILE is required")?,
            admin_token,
            bind: env::var("SENTINEL_BIND")
                .unwrap_or_else(|_| "127.0.0.1:8080".into())
                .parse()
                .context("invalid SENTINEL_BIND")?,
            nats_url: env::var("SENTINEL_NATS_URL")
                .unwrap_or_else(|_| "nats://127.0.0.1:4222".into()),
            nats_token: secret("SENTINEL_NATS_TOKEN")?,
            web_dir: env::var("SENTINEL_WEB_DIR")
                .unwrap_or_else(|_| "web/dist".into())
                .into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        path::{Path, PathBuf},
        process::Command,
        time::{SystemTime, UNIX_EPOCH},
    };

    /// Set in a child process to select which assertion the test binary runs.
    /// We exercise the real `Config::load` while never mutating the test
    /// process environment, so sibling tests that read env cannot race.
    const CHILD_MODE: &str = "SENTINEL_CONFIG_TEST_CHILD";
    const CHILD_TEST: &str = "config::tests::database_url_sources_and_conflicts";

    fn child(mode: &str, url_file: Option<&Path>) -> Command {
        let mut command = Command::new(env::current_exe().expect("current test binary"));
        command
            .env_clear()
            .env(CHILD_MODE, mode)
            .env("SENTINEL_ADMIN_TOKEN", "x".repeat(32))
            .args(["--exact", CHILD_TEST, "--nocapture", "--test-threads=1"]);
        match mode {
            "file" => {
                command.env(
                    "SENTINEL_DATABASE_URL_FILE",
                    url_file.expect("url file path"),
                );
            }
            "env" => {
                command.env("SENTINEL_DATABASE_URL", "postgres://from-env");
            }
            "conflict" => {
                command
                    .env("SENTINEL_DATABASE_URL", "postgres://from-env")
                    .env(
                        "SENTINEL_DATABASE_URL_FILE",
                        url_file.expect("url file path"),
                    );
            }
            other => panic!("unknown child mode {other}"),
        }
        command
    }

    fn run(mut command: Command, mode: &str) {
        let output = command.output().expect("run child test process");
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Guard against a filtering typo silently running zero tests: the
        // child only prints this marker from the matching assertion branch.
        let marker = format!("SENTINEL_CONFIG_CHILD_OK:{mode}");
        assert!(
            output.status.success(),
            "child ({mode}) failed\nstdout:\n{stdout}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stderr),
        );
        assert!(
            stdout.contains(&marker),
            "child ({mode}) did not run the expected test\nstdout:\n{stdout}",
        );
    }

    #[test]
    fn database_url_sources_and_conflicts() {
        if let Ok(mode) = env::var(CHILD_MODE) {
            match mode.as_str() {
                "file" => {
                    let config = Config::load().expect("load database URL from file");
                    assert_eq!(config.database_url, "postgres://from-file");
                }
                "env" => {
                    let config = Config::load().expect("load database URL from env");
                    assert_eq!(config.database_url, "postgres://from-env");
                }
                "conflict" => match Config::load() {
                    Ok(_) => panic!("both sources must be rejected"),
                    Err(error) => assert!(
                        format!("{error:#}").contains("mutually exclusive"),
                        "unexpected error: {error:#}",
                    ),
                },
                other => panic!("unknown child mode {other}"),
            }
            println!("SENTINEL_CONFIG_CHILD_OK:{mode}");
            return;
        }

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let url_file: PathBuf = env::temp_dir().join(format!(
            "sentinel-database-url-{}-{unique}",
            std::process::id()
        ));
        fs::write(&url_file, "postgres://from-file\n").expect("write url file");

        run(child("file", Some(&url_file)), "file");
        run(child("env", None), "env");
        run(child("conflict", Some(&url_file)), "conflict");

        let _ = fs::remove_file(&url_file);
    }
}
