//! `verify`: end-to-end sanity checks run at the tail of bootstrap. Exits non-zero on
//! any failure so a broken firewall fails loudly instead of leaving a silently-broken
//! container.

use std::path::Path;
use std::process::Stdio;

use anyhow::{Result, bail};
use tokio::process::Command;
use tracing::{error, info};

use crate::setup::READY_PATH;

/// Run verification. `blocked` hosts must be unreachable; `allowed` hosts must be
/// reachable. Returns an error if any expectation is violated.
pub async fn run(blocked: &[String], allowed: &[String]) -> Result<()> {
    let mut failures = 0;

    // Daemon liveness: the readiness file must exist.
    if Path::new(READY_PATH).exists() {
        info!("OK: resolver readiness file present");
    } else {
        error!("FAIL: resolver readiness file {READY_PATH} missing — daemon not up?");
        failures += 1;
    }

    for host in blocked {
        if can_reach(host).await {
            error!("FAIL: reached blocked host {host} (should be denied)");
            failures += 1;
        } else {
            info!("OK: blocked host {host} is unreachable as expected");
        }
    }

    for host in allowed {
        if can_reach(host).await {
            info!("OK: allowed host {host} is reachable");
        } else {
            error!("FAIL: could not reach allowed host {host}");
            failures += 1;
        }
    }

    if failures > 0 {
        bail!("firewall verification failed: {failures} check(s) failed");
    }
    info!("firewall verification passed");
    Ok(())
}

/// True if an HTTPS connection to `host` can be established within 5s.
async fn can_reach(host: &str) -> bool {
    Command::new("curl")
        .args([
            "--connect-timeout",
            "5",
            "-sS",
            "-o",
            "/dev/null",
            &format!("https://{host}"),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false)
}
