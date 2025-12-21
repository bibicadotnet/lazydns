use crate::Result;
use crate::config::types::PluginConfig;
use crate::plugin::Context;
use crate::plugin::factory as plugin_factory;
use crate::plugin::traits::Plugin;
use async_trait::async_trait;
use chrono::{Local, Utc};
use cron::Schedule;
use reqwest::Client;
use serde_yaml::Value;
use std::any::Any;
use std::fmt::Debug;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::process::Command;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{info, warn};

crate::register_plugin_builder!(CronPlugin);

/// Cron plugin: supports multiple jobs, cron expressions, HTTP actions, shell commands and invoking other plugins.
///
/// Example config:
/// ```yaml
/// args:
///   jobs:
///     - name: call_http
///       interval_seconds: 5
///       action:
///         http:
///           method: GET
///           url: http://127.0.0.1:8080/ping
///     - name: invoke_cache
///       cron: "0/10 * * * * *"
///       action:
///         invoke_plugin:
///           type: cache
///           args:
///             size: 10
///     - name: run_cmd
///       interval_seconds: 2
///       action:
///         command: "echo hello > /tmp/cron_test.txt"
/// ```
#[derive(Debug)]
pub struct CronPlugin {
    jobs: Mutex<Vec<JobHandle>>,
    stop_tx: watch::Sender<bool>,
}

#[derive(Debug)]
struct JobHandle {
    _name: String,
    _stop_tx: watch::Sender<bool>,
    handle: JoinHandle<()>,
}

#[derive(Debug)]
enum ScheduleDef {
    Interval(u64),
    /// Second field: if true, use machine local timezone; otherwise use UTC
    Cron(Box<Schedule>, bool),
}

#[derive(Debug)]
enum JobAction {
    Http {
        method: String,
        url: String,
        body: Option<String>,
    },
    InvokePlugin {
        plugin_type: String,
        plugin_args: Option<Value>,
    },
    Command {
        cmd: String,
    },
}

impl CronPlugin {
    pub fn new() -> Self {
        let (tx, _rx) = watch::channel(false);
        Self {
            jobs: Mutex::new(Vec::new()),
            stop_tx: tx,
        }
    }

    fn spawn_job(&self, name: String, sched: ScheduleDef, action: JobAction) {
        let mut parent_stop_rx = self.stop_tx.subscribe();
        let (job_stop_tx, mut job_stop_rx) = watch::channel(false);
        let client = Client::new();

        let task_name = name.clone();
        let handle = tokio::spawn(async move {
            let name = task_name;
            loop {
                // determine next delay
                let delay = match &sched {
                    ScheduleDef::Interval(s) => Duration::from_secs(*s),
                    ScheduleDef::Cron(schedule, use_local) => {
                        // compute next occurrence in local timezone (or UTC)
                        // normalize to UTC so both branches have the same DateTime type
                        let next = if *use_local {
                            schedule
                                .upcoming(Local)
                                .next()
                                .map(|dt| dt.with_timezone(&Utc))
                        } else {
                            schedule.upcoming(Utc).next()
                        };
                        match next {
                            Some(dt) => {
                                // normalize both times to UTC for duration calculation
                                let dt_utc = dt.with_timezone(&Utc);
                                let now = Utc::now();
                                let dur = dt_utc.signed_duration_since(now);
                                if dur.num_milliseconds() <= 0 {
                                    Duration::from_millis(10)
                                } else {
                                    Duration::from_millis(dur.num_milliseconds() as u64)
                                }
                            }
                            None => {
                                warn!(job=%name, "cron: no upcoming schedule items, stopping job");
                                break;
                            }
                        }
                    }
                };

                let start = Instant::now();
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {
                        match &action {
                            JobAction::Http { method, url, body } => {
                                let m = method.clone(); let u = url.clone(); let b = body.clone(); let client = client.clone();
                                let job_name = name.clone();
                                tokio::spawn(async move {
                                    let req = client.request(m.parse().unwrap_or(reqwest::Method::GET), &u);
                                    let req = if let Some(body) = b { req.body(body) } else { req };
                                    match req.send().await {
                                        Ok(resp) => info!(job=%job_name, status = %resp.status(), "http action succeeded"),
                                        Err(e) => warn!(job=%job_name, error=%e, "http action failed"),
                                    }
                                });
                            }
                            JobAction::InvokePlugin { plugin_type, plugin_args } => {
                                let mut pconf = PluginConfig::new(plugin_type.clone());
                                if let Some(args) = plugin_args { pconf.args = args.clone(); }
                                if let Some(factory) = plugin_factory::get_plugin_factory(plugin_type.as_str()) {
                                    if let Ok(instance) = factory.create(&pconf) {
                                        let mut ctx = Context::new(crate::dns::Message::new());
                                        let plugin = instance.clone();
                                        let job_name = name.clone();
                                        tokio::spawn(async move {
                                            if let Err(e) = plugin.execute(&mut ctx).await { warn!(job=%job_name, error=%e, "invoke_plugin failed"); }
                                            else { info!(job=%job_name, "invoke_plugin executed"); }
                                        });
                                    } else { warn!(job=%name, plugin=%plugin_type, "factory create failed"); }
                                } else { warn!(job=%name, plugin=%plugin_type, "factory not found"); }
                            }
                            JobAction::Command { cmd } => {
                                let c = cmd.clone();
                                let job_name = name.clone();
                                tokio::spawn(async move {
                                    #[cfg(windows)]
                                    let mut command = Command::new("cmd");
                                    #[cfg(not(windows))]
                                    let mut command = Command::new("sh");

                                    #[cfg(windows)]
                                    { command.arg("/C").arg(c); }
                                    #[cfg(not(windows))]
                                    { command.arg("-c").arg(c); }

                                    match command.status().await {
                                        Ok(st) => info!(job=%job_name, status = ?st, "command executed"),
                                        Err(e) => warn!(job=%job_name, error=%e, "command execution failed"),
                                    }
                                });
                            }
                        }
                    }
                    _ = parent_stop_rx.changed() => { if *parent_stop_rx.borrow() { info!(job=%name, "global stop"); break; } }
                    _ = job_stop_rx.changed() => { if *job_stop_rx.borrow() { info!(job=%name, "job stop"); break; } }
                }

                let elapsed = Instant::now().duration_since(start);
                if elapsed < Duration::from_millis(10) {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        });

        let mut jobs = self.jobs.lock().unwrap();
        jobs.push(JobHandle {
            _name: name,
            _stop_tx: job_stop_tx,
            handle,
        });
    }
}

impl Default for CronPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Plugin for CronPlugin {
    async fn execute(&self, _ctx: &mut Context) -> Result<()> {
        Ok(())
    }
    fn name(&self) -> &str {
        "cron"
    }
    fn as_any(&self) -> &dyn Any {
        self
    }

    async fn shutdown(&self) -> Result<()> {
        let _ = self.stop_tx.send(true);
        let jobs = std::mem::take(&mut *self.jobs.lock().unwrap());
        for j in jobs {
            let _ = j.handle.await;
        }
        Ok(())
    }

    fn init(config: &PluginConfig) -> Result<std::sync::Arc<dyn Plugin>> {
        let plugin = CronPlugin::new();

        if let Value::Mapping(map) = &config.args
            && let Some(Value::Sequence(jobs)) = map.get(Value::String("jobs".to_string()))
        {
            for jb in jobs.iter() {
                if let Value::Mapping(jmap) = jb {
                    let name = jmap
                        .get(Value::String("name".to_string()))
                        .and_then(|v| v.as_str())
                        .unwrap_or("job")
                        .to_string();

                    let sched = if let Some(Value::Number(n)) =
                        jmap.get(Value::String("interval_seconds".to_string()))
                    {
                        if let Some(sec) = n.as_u64() {
                            ScheduleDef::Interval(sec)
                        } else {
                            ScheduleDef::Interval(1)
                        }
                    } else if let Some(Value::String(expr)) =
                        jmap.get(Value::String("cron".to_string()))
                    {
                        // timezone support: we now use machine local timezone for cron schedules.
                        // If user specified a timezone value it will be ignored and a warning emitted.
                        let tz_present = jmap.get(Value::String("timezone".to_string())).is_some();
                        if tz_present {
                            warn!(job=%name, "timezone in config ignored; using machine local timezone instead");
                        }
                        match Schedule::from_str(expr) {
                            Ok(s) => ScheduleDef::Cron(Box::new(s), tz_present),
                            Err(e) => {
                                warn!(job=%name, error=%e, "invalid cron expression, skipping");
                                continue;
                            }
                        }
                    } else {
                        ScheduleDef::Interval(1)
                    };

                    let action = if let Some(Value::Mapping(act)) =
                        jmap.get(Value::String("action".to_string()))
                    {
                        if let Some(Value::Mapping(http)) =
                            act.get(Value::String("http".to_string()))
                        {
                            let method = http
                                .get(Value::String("method".to_string()))
                                .and_then(|v| v.as_str())
                                .unwrap_or("GET")
                                .to_string();
                            let url = http
                                .get(Value::String("url".to_string()))
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let body = http
                                .get(Value::String("body".to_string()))
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string());
                            JobAction::Http { method, url, body }
                        } else if let Some(Value::Mapping(inv)) =
                            act.get(Value::String("invoke_plugin".to_string()))
                        {
                            let ptype = inv
                                .get(Value::String("type".to_string()))
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let pargs = inv.get(Value::String("args".to_string())).cloned();
                            JobAction::InvokePlugin {
                                plugin_type: ptype,
                                plugin_args: pargs,
                            }
                        } else if let Some(Value::String(cmd)) =
                            act.get(Value::String("command".to_string()))
                        {
                            JobAction::Command {
                                cmd: cmd.to_string(),
                            }
                        } else {
                            warn!(job=%name, "unknown action type, skipping");
                            continue;
                        }
                    } else {
                        warn!(job=%name, "no action defined, skipping");
                        continue;
                    };

                    plugin.spawn_job(name, sched, action);
                }
            }
        }

        Ok(Arc::new(plugin))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::PluginConfig;
    use serde_yaml::{Mapping, Value};
    use std::sync::Arc as StdArc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn test_interval_jobs_and_invoke_plugin() {
        // Register a test plugin factory
        #[derive(Debug)]
        struct TestInvoke(StdArc<AtomicUsize>);
        #[async_trait]
        impl Plugin for TestInvoke {
            async fn execute(&self, _ctx: &mut Context) -> Result<()> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
            fn name(&self) -> &str {
                "testinvoke"
            }
        }
        // Implement init
        impl TestInvoke {
            fn init_with_counter(counter: StdArc<AtomicUsize>) -> std::sync::Arc<dyn Plugin> {
                StdArc::new(TestInvoke(counter))
            }
        }
        // Register a simple factory
        struct F(StdArc<AtomicUsize>);
        impl plugin_factory::PluginFactory for F {
            fn create(
                &self,
                _config: &crate::config::types::PluginConfig,
            ) -> crate::Result<std::sync::Arc<dyn Plugin>> {
                Ok(TestInvoke::init_with_counter(StdArc::clone(&self.0)))
            }
            fn plugin_type(&self) -> &'static str {
                "testinvoke"
            }
            fn aliases(&self) -> Vec<&'static str> {
                Vec::new()
            }
        }

        let counter = StdArc::new(AtomicUsize::new(0));
        plugin_factory::register_plugin_factory(StdArc::new(F(StdArc::clone(&counter))));

        let mut pconf = PluginConfig::new("cron".to_string());
        // build jobs sequence
        let mut job1 = Mapping::new();
        job1.insert(
            Value::String("name".to_string()),
            Value::String("invoke1".to_string()),
        );
        job1.insert(
            Value::String("interval_seconds".to_string()),
            Value::Number(serde_yaml::Number::from(1)),
        );
        let mut action = Mapping::new();
        let mut inv = Mapping::new();
        inv.insert(
            Value::String("type".to_string()),
            Value::String("testinvoke".to_string()),
        );
        action.insert(
            Value::String("invoke_plugin".to_string()),
            Value::Mapping(inv),
        );
        job1.insert(Value::String("action".to_string()), Value::Mapping(action));

        let jobs = Value::Sequence(vec![Value::Mapping(job1)]);
        let mut args = Mapping::new();
        args.insert(Value::String("jobs".to_string()), jobs);
        pconf.args = Value::Mapping(args);

        let plugin = CronPlugin::init(&pconf).unwrap();
        // plugin spawned job; wait a bit
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert!(counter.load(Ordering::SeqCst) >= 1);
        plugin.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_http_job() {
        // Start a tiny TCP server to accept one HTTP request
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let _ = socket
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    .await;
            }
        });

        let mut pconf = PluginConfig::new("cron".to_string());
        let mut job = Mapping::new();
        job.insert(
            Value::String("name".to_string()),
            Value::String("http1".to_string()),
        );
        job.insert(
            Value::String("interval_seconds".to_string()),
            Value::Number(serde_yaml::Number::from(1)),
        );
        let mut action = Mapping::new();
        let mut http = Mapping::new();
        http.insert(
            Value::String("method".to_string()),
            Value::String("GET".to_string()),
        );
        http.insert(
            Value::String("url".to_string()),
            Value::String(format!("http://{}/", addr)),
        );
        action.insert(Value::String("http".to_string()), Value::Mapping(http));
        job.insert(Value::String("action".to_string()), Value::Mapping(action));

        let jobs = Value::Sequence(vec![Value::Mapping(job)]);
        let mut args = Mapping::new();
        args.insert(Value::String("jobs".to_string()), jobs);
        pconf.args = Value::Mapping(args);

        let plugin = CronPlugin::init(&pconf).unwrap();

        tokio::time::sleep(Duration::from_millis(1500)).await;

        plugin.shutdown().await.unwrap();
        let _ = server.await;
    }

    #[tokio::test]
    async fn test_command_job() {
        // Create a temp file path
        let mut path = std::env::temp_dir();
        path.push("cron_cmd_test.txt");
        let path_str = path.to_string_lossy().to_string();

        // Create a job that writes into the file
        let mut pconf = PluginConfig::new("cron".to_string());
        let mut job = Mapping::new();
        job.insert(
            Value::String("name".to_string()),
            Value::String("cmd1".to_string()),
        );
        job.insert(
            Value::String("interval_seconds".to_string()),
            Value::Number(serde_yaml::Number::from(1)),
        );
        let mut action = Mapping::new();
        // choose platform command
        #[cfg(windows)]
        let cmd = format!("cmd /C echo hello > {}", path_str);
        #[cfg(not(windows))]
        let cmd = format!("sh -c 'echo hello > {}'", path_str);
        action.insert(Value::String("command".to_string()), Value::String(cmd));
        job.insert(Value::String("action".to_string()), Value::Mapping(action));

        let jobs = Value::Sequence(vec![Value::Mapping(job)]);
        let mut args = Mapping::new();
        args.insert(Value::String("jobs".to_string()), jobs);
        pconf.args = Value::Mapping(args);

        // ensure file does not exist
        let _ = std::fs::remove_file(&path);

        let plugin = CronPlugin::init(&pconf).unwrap();
        tokio::time::sleep(Duration::from_millis(1500)).await;
        plugin.shutdown().await.unwrap();

        // file should exist
        assert!(path.exists());
        // cleanup
        let _ = std::fs::remove_file(&path);
    }
}
