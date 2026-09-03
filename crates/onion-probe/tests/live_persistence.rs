#![cfg(unix)]

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use onion_probe::StartupRecord;

const STARTUP_TIMEOUT: Duration = Duration::from_secs(300);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(20);

#[test]
fn persistent_state_restores_the_same_onion_identity_without_a_tcp_listener() {
    if std::env::var("DEADDROP_LIVE_TOR").as_deref() != Ok("1") {
        eprintln!("skipped: set DEADDROP_LIVE_TOR=1 to run the live Tor probe");
        return;
    }

    let state = tempfile::tempdir().expect("temporary Tor state directory should be created");
    let first = launch_once(state.path());
    let second = launch_once(state.path());

    assert_eq!(first.onion_url, second.onion_url);
    assert_eq!(first.state_dir, state.path());
    assert_eq!(second.state_dir, state.path());
}

fn launch_once(state_dir: &std::path::Path) -> StartupRecord {
    let mut child = ManagedChild::spawn(state_dir);
    let stdout = child.child.stdout.take().expect("stdout should be piped");
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut line = String::new();
        let result = BufReader::new(stdout).read_line(&mut line).map(|_| line);
        let _ = sender.send(result);
    });

    let line = receiver
        .recv_timeout(STARTUP_TIMEOUT)
        .expect("onion service did not publish before the startup timeout")
        .expect("startup record should be readable");
    let startup: StartupRecord =
        serde_json::from_str(line.trim()).expect("first stdout line should be a startup record");

    assert_no_tcp_listener(child.child.id());
    child.stop_cleanly();
    startup
}

fn assert_no_tcp_listener(pid: u32) {
    let inspect = Command::new("lsof")
        .args(["-Pan", "-p", &pid.to_string()])
        .output()
        .expect("lsof is required for the live Tor probe");
    assert!(
        inspect.status.success(),
        "lsof could not inspect the onion probe process: {}",
        String::from_utf8_lossy(&inspect.stderr)
    );

    let output = Command::new("lsof")
        .args(["-Pan", "-p", &pid.to_string(), "-iTCP", "-sTCP:LISTEN"])
        .output()
        .expect("lsof is required for the live Tor probe");

    assert!(
        output.status.code() == Some(1) && output.stdout.is_empty(),
        "TCP listener inspection failed or found a listener (status {}):\n{}{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

struct ManagedChild {
    child: Child,
}

impl ManagedChild {
    fn spawn(state_dir: &std::path::Path) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_onion-probe"))
            .arg(state_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("onion probe should start");
        Self { child }
    }

    fn stop_cleanly(&mut self) {
        let status = Command::new("kill")
            .args(["-INT", &self.child.id().to_string()])
            .status()
            .expect("shutdown signal should be sent");
        assert!(status.success(), "shutdown signal should succeed");

        let deadline = Instant::now() + SHUTDOWN_TIMEOUT;
        loop {
            match self
                .child
                .try_wait()
                .expect("child status should be readable")
            {
                Some(status) => {
                    assert!(status.success(), "onion probe exited with {status}");
                    break;
                }
                None if Instant::now() < deadline => thread::sleep(Duration::from_millis(100)),
                None => panic!("onion probe did not shut down within {SHUTDOWN_TIMEOUT:?}"),
            }
        }
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
