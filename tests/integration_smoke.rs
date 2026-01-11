use std::net::TcpListener;
use std::os::unix::process::ExitStatusExt;
use std::process::Stdio;
use std::time::Duration;

use tempfile::tempdir;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::time::timeout;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn integration_smoke_test_config_reload_and_watcher() -> Result<(), Box<dyn std::error::Error>>
{
    // Reserve an ephemeral port to reduce flakiness
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener);

    let tmp = tempdir()?;
    let hosts_path = tmp.path().join("hosts.txt");
    let cfg_path = tmp.path().join("config.yaml");

    // Write initial hosts file
    std::fs::write(&hosts_path, "127.0.0.1 example.local\n")?;

    // Create a minimal config with admin enabled and hosts plugin auto_reload
    let cfg_contents = format!(
        "log:\n  level: info\n  console: true\nadmin:\n  enabled: true\n  addr: \"127.0.0.1:{}\"\nplugins:\n  - tag: hosts\n    type: hosts\n    args:\n      files:\n        - \"{}\"\n      auto_reload: true\n",
        port,
        hosts_path.display()
    );
    std::fs::write(&cfg_path, cfg_contents)?;

    // Build the binary with admin feature to ensure admin API is available
    let build_status = tokio::process::Command::new("cargo")
        .args([
            "build",
            "-p",
            "lazydns",
            "--features",
            "admin,log-ansi",
            "--bin",
            "lazydns",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await?;
    assert!(
        build_status.success(),
        "failed to build lazydns with admin feature"
    );

    // Locate the built binary
    let mut bin_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    bin_path.push("target/debug/lazydns");

    let mut child = Command::new(bin_path)
        .arg("-c")
        .arg(cfg_path.as_os_str())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let stdout = child.stdout.take().expect("child stdout");
    let stderr = child.stderr.take().expect("child stderr");

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

    // Spawn readers to collect logs
    tokio::spawn(read_lines(BufReader::new(stdout), tx.clone()));
    tokio::spawn(read_lines(BufReader::new(stderr), tx));

    // Wait for server initialization
    wait_for_log(
        &mut rx,
        "lazydns initialized successfully",
        Duration::from_secs(20),
    )
    .await?;

    // Try connecting to the admin endpoint until it becomes reachable
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()?;
    let url = format!("http://127.0.0.1:{}/api/config/reload", port);

    let mut ok = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(12);
    while tokio::time::Instant::now() < deadline {
        if let Ok(res) = client.post(&url).json(&serde_json::json!({})).send().await
            && res.status().is_success()
        {
            ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    if !ok {
        // Collect remaining logs (non-blocking) for diagnostics
        let mut remaining = Vec::new();
        while let Ok(Some(line)) = tokio::time::timeout(Duration::from_millis(100), rx.recv()).await
        {
            remaining.push(line);
        }

        // Check child status
        let status = match child.try_wait() {
            Ok(Some(s)) => format!("exited: {:?}", s),
            Ok(None) => "running".to_string(),
            Err(err) => format!("wait error: {}", err),
        };

        panic!(
            "admin endpoint never became reachable; recent logs: {:?}; child status: {}",
            remaining, status
        );
    }

    // Trigger hosts file change
    std::fs::write(&hosts_path, "127.0.0.1 changed.example\n")?;

    // Wait for scheduled auto-reload log
    wait_for_log(
        &mut rx,
        "scheduled auto-reload completed",
        Duration::from_secs(20),
    )
    .await?;

    // Send SIGTERM (use kill command to ensure SIGTERM is delivered)
    if let Some(pid) = child.id() {
        // use system kill to send TERM so process can do graceful shutdown
        let _ = std::process::Command::new("kill")
            .arg("-TERM")
            .arg(pid.to_string())
            .status();
    }

    // Wait for shutdown message
    wait_for_log(
        &mut rx,
        "Shutdown finished successfully",
        Duration::from_secs(20),
    )
    .await?;

    // Ensure child has exited
    let status = timeout(Duration::from_secs(5), child.wait()).await??;
    assert!(
        status.success() || status.signal().is_some(),
        "child did not exit cleanly"
    );

    Ok(())
}

async fn read_lines<R: tokio::io::AsyncRead + Unpin + Send + 'static>(
    mut rdr: BufReader<R>,
    tx: tokio::sync::mpsc::UnboundedSender<String>,
) {
    let mut s = String::new();
    loop {
        s.clear();
        match rdr.read_line(&mut s).await {
            Ok(0) => break, // EOF
            Ok(_) => {
                // Trim and forward
                let _ = tx.send(s.trim().to_string());
            }
            Err(_) => break,
        }
    }
}

async fn wait_for_log(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<String>,
    needle: &str,
    timeout_dur: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::collections::VecDeque;
    let mut recent: VecDeque<String> = VecDeque::with_capacity(50);
    let deadline = tokio::time::Instant::now() + timeout_dur;
    loop {
        if tokio::time::Instant::now() > deadline {
            // Drain any remaining lines (non-blocking) to include in error message
            let mut remaining = Vec::new();
            while let Ok(Some(line)) =
                tokio::time::timeout(Duration::from_millis(50), rx.recv()).await
            {
                remaining.push(line);
            }
            let mut msg = format!("timeout waiting for log: {}\nRecent logs:\n", needle);
            for l in recent.iter() {
                msg.push_str(&format!("  {}\n", l));
            }
            for l in remaining.iter() {
                msg.push_str(&format!("  {}\n", l));
            }
            return Err(msg.into());
        }
        match tokio::time::timeout(deadline - tokio::time::Instant::now(), rx.recv()).await {
            Ok(Some(line)) => {
                if recent.len() == 50 {
                    recent.pop_front();
                }
                recent.push_back(line.clone());
                if line.contains(needle) {
                    return Ok(());
                }
            }
            Ok(None) => return Err("log channel closed".into()),
            Err(_) => return Err(format!("timeout waiting for log: {}", needle).into()),
        }
    }
}
