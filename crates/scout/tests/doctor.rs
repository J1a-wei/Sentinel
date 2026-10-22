use anyhow::{Context, Result};
use serde_json::Value;
use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

fn run(command: &str, state: &Path, root: &Path, mode: &str, network: &str) -> Result<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_scout"))
        .arg(command)
        .env_clear()
        .env("SENTINEL_STATE_DIR", state)
        .env("SENTINEL_HOST_ROOT", root)
        .env("SENTINEL_RUNTIME_MODE", mode)
        .env("SENTINEL_NETWORK_PROC_PREFIX", network)
        // Either secret lookup would fail. Doctor/status must never look it up.
        .env("SENTINEL_ADMIN_TOKEN", "fictional-do-not-read")
        .env(
            "SENTINEL_ADMIN_TOKEN_FILE",
            state.join("absent-admin-secret"),
        )
        .env("SENTINEL_NATS_TOKEN", "fictional-do-not-read")
        .env("SENTINEL_NATS_TOKEN_FILE", state.join("absent-nats-secret"))
        .output()?)
}

#[test]
fn doctor_is_read_only_without_state_registration_or_credentials() -> Result<()> {
    let fixture = tempfile::tempdir()?;
    let root = fixture.path().join("host");
    let state = fixture.path().join("must-not-create-state");
    fs::create_dir_all(root.join("proc/42/net"))?;
    let result = run("doctor", &state, &root, "container", "proc/42/net")?;
    assert!(result.status.success());
    let report: Value = serde_json::from_slice(&result.stdout)?;
    assert_eq!(report["requested_mode"], "container");
    assert_eq!(report["selected_mode"], "container");
    assert_eq!(report["host_root"], root.to_str().context("fixture path")?);
    assert_eq!(report["network_proc_prefix"], "proc/42/net");
    assert_eq!(report["network_source_status"], "available");
    assert_eq!(report["collection_allowed"], true);
    assert!(report.get("installation_id").is_none());
    assert!(report.get("asset_id").is_none());
    assert!(!state.exists());
    assert_eq!(fs::read_dir(fixture.path())?.count(), 1);
    assert_eq!(fs::read_dir(root.join("proc/42/net"))?.count(), 0);
    Ok(())
}

#[test]
fn doctor_reports_missing_root_and_fails_without_initialization() -> Result<()> {
    let fixture = tempfile::tempdir()?;
    let root = fixture.path().join("missing-host");
    let state = fixture.path().join("missing-state");
    let result = run("doctor", &state, &root, "container", "proc/1/net")?;
    assert!(!result.status.success());
    let report: Value = serde_json::from_slice(&result.stdout)?;
    assert_eq!(report["host_root"], root.to_str().context("fixture path")?);
    assert_eq!(report["host_root_status"], "missing");
    assert_eq!(report["collection_allowed"], false);
    assert_eq!(fs::read_dir(fixture.path())?.count(), 0);
    // The collection path fails before opening state as well.
    assert!(
        !run("once", &state, &root, "container", "proc/1/net")?
            .status
            .success()
    );
    assert_eq!(fs::read_dir(fixture.path())?.count(), 0);
    Ok(())
}

#[test]
fn status_preserves_its_contract_and_ignores_collection_configuration() -> Result<()> {
    let fixture = tempfile::tempdir()?;
    let state = fixture.path().join("state");
    let root = fixture.path().join("missing-host");
    let initialized = run("init", &state, &root, "invalid-mode", "../invalid")?;
    assert!(initialized.status.success());
    let original: Value = serde_json::from_slice(&initialized.stdout)?;
    let result = run("status", &state, &root, "invalid-mode", "../invalid")?;
    assert!(result.status.success());
    let status: Value = serde_json::from_slice(&result.stdout)?;
    assert_eq!(status, original);
    assert_eq!(status.as_object().context("status object")?.len(), 4);
    Ok(())
}
