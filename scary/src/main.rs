pub mod programs;

use crate::programs::{get_ebpf_path, MapBuilder, ProgramBuilder};
use aya::{
    include_bytes_aligned, maps::PerfEventArray, programs::TracePoint, util::online_cpus, Ebpf,
};
use aya_log::EbpfLogger;
use base64::{engine::general_purpose, Engine as _};
use bytes::BytesMut;
use chrono::{DateTime, Utc};
use clap::Parser;
use config::{Config, File};
use log::{debug, error, info, warn};
use nix::sys::utsname::uname;
use nix::unistd::User;
use scary_ebpf_common::{EventData, EVENT_DATA_ARGS};
use scary_logger_plugins::s3::{S3Logger, S3LoggerConfig};
use scary_userspace_common::logger::config::LoggerConfig;
use scary_userspace_common::logger::LoggerPlugin;
use serde::{Deserialize, Serialize};
use serde_json;
use serde_json::Value;
use std::convert::TryFrom;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::{
    fs,
    io::{self, Write},
    str,
};
use tokio::signal;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

lazy_static::lazy_static! {
    static ref EXEC_ENTER: ProgramBuilder = ProgramBuilder::new(
        "syscalls",
        "sys_enter_execve",
        "handle_exec",
        "tracepoint",
    );

    static ref EXEC_EXIT: ProgramBuilder = ProgramBuilder::new(
        "sched",
        "sched_process_exec",
        "handle_exec_exit",
        "tracepoint",
    );

    static ref EVENTS_MAP: MapBuilder = MapBuilder::new("EVENTS");
}

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

struct AgentConfig {
    ip_blocking: bool,
    logging: bool,
}

impl Default for AgentConfig {
    fn default() -> Self {
        AgentConfig {
            ip_blocking: false,
            logging: true,
        }
    }
}

fn get_boot_time() -> Option<u64> {
    // Read the system boot time from /proc/uptime
    if let Ok(contents) = fs::read_to_string("/proc/uptime") {
        let uptime_secs: f64 = contents
            .split_whitespace()
            .next()
            .unwrap_or("0")
            .parse()
            .ok()?;
        let boot_time = Utc::now().timestamp() as u64 - uptime_secs as u64;
        return Some(boot_time * 1_000_000_000);
    }
    None
}

struct UserSpaceEventData(EventData);

#[derive(Debug, Serialize, Deserialize)]
struct NetworkConnectionJson {
    local_addr: String,
    local_port: u16,
    remote_addr: String,
    remote_port: u16,
    protocol: String,
    socket_type: String,
    socket_state: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct EventJson {
    exec_id: String,
    pid: u32,
    ppid: u32,
    tid: u32,
    uid: u32,
    gid: u32,
    comm: String,
    cwd: String,
    binary: String,
    args: Vec<String>,
    username: String,
    hostname: String,
    timestamp: String,
    // network_connections: Vec<NetworkConnectionJson>,
}

impl UserSpaceEventData {
    fn to_json(&self) -> EventJson {
        EventJson {
            exec_id: self.get_exec_id(),
            hostname: Self::get_hostname(),
            pid: self.0.event.pid,
            ppid: self.0.event.ppid,
            tid: self.0.event.tid,
            uid: self.0.event.uid,
            gid: self.0.event.gid,
            comm: self.get_comm(),
            binary: self.get_filename(),
            cwd: self.get_cwd(),
            args: self.get_args(),
            username: self.get_username(),
            timestamp: Self::format_timestamp(self.0.event.timestamp_ns),
            // network_connections: self.get_network_connections(),
        }
    }

    fn get_exec_id(&self) -> String {
        // Convert the exec_id bytes to a base64 string
        general_purpose::STANDARD.encode(&self.0.event.exec_id)
    }

    fn format_timestamp(timestamp_ns: u64) -> String {
        if let Some(boot_time_ns) = get_boot_time() {
            let real_timestamp_ns = boot_time_ns + timestamp_ns;

            match i64::try_from(real_timestamp_ns) {
                Ok(timestamp_ns_i64) => {
                    let datetime = DateTime::<Utc>::from_timestamp_nanos(timestamp_ns_i64);
                    return datetime.to_rfc3339();
                }
                Err(_) => return "<invalid timestamp>".to_string(),
            }
        }
        "<invalid timestamp>".to_string()
    }

    fn get_comm(&self) -> String {
        println!("Debug: Raw comm bytes: {:?}", &self.0.event.comm);
        let comm_str = str::from_utf8(&self.0.event.comm)
            .map(|s| {
                let trimmed = s.trim_end_matches('\0');
                println!("Debug: Trimmed comm string: {:?}", trimmed);
                trimmed.to_string()
            })
            .unwrap_or_else(|e| {
                println!("Debug: UTF-8 conversion error: {:?}", e);
                "<invalid utf8>".to_string()
            });
        println!("Debug: Final comm string: {:?}", comm_str);
        comm_str
    }

    fn get_filename(&self) -> String {
        str::from_utf8(&self.0.event.filename)
            .map(|s| s.trim_end_matches('\0').to_string())
            .unwrap_or_else(|_| "<invalid utf8>".to_string())
    }

    fn get_cwd(&self) -> String {
        let cwd_len = self.0.event.cwd_len as usize;
        println!("Debug: CWD raw bytes: {:?}", &self.0.event.cwd[..cwd_len]);
        println!("Debug: CWD length: {}", cwd_len);

        // Convert the raw bytes into a string
        let raw_cwd = match str::from_utf8(&self.0.event.cwd[..cwd_len]) {
            Ok(s) => s.to_string(),
            Err(e) => {
                println!("Debug: UTF-8 conversion error: {:?}", e);
                return "<invalid utf8>".to_string();
            }
        };

        println!("Debug: Raw CWD string: {:?}", raw_cwd);

        // Split the path into components
        let components: Vec<&str> = raw_cwd.split('/').filter(|s| !s.is_empty()).collect();

        // Reverse the components to get the correct order
        let mut reversed_components = components;
        reversed_components.reverse();

        // Join the components back into a path
        let reversed_cwd = format!("/{}", reversed_components.join("/"));

        println!("Debug: Reversed CWD string: {:?}", reversed_cwd);

        reversed_cwd
    }

    fn get_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        let total_size = self.0.args_read_result as usize;
        let args_data = &self.0.args[..total_size];
        println!("Debug: args_data {:?}", args_data);
        println!("Debug: total_size {:?}", total_size);

        let mut start = 0;
        while start < total_size {
            // Find the end of the current argument (null byte or end of data)
            let end = args_data[start..]
                .iter()
                .position(|&x| x == b'\0')
                .unwrap_or(total_size - start);

            let arg_bytes = &args_data[start..start + end];
            println!("Debug: Arg bytes: {:?}", arg_bytes);

            if let Ok(s) = std::str::from_utf8(arg_bytes) {
                if !s.is_empty() {
                    println!("We have some data: {}", s);
                    args.push(s.to_string());
                } else {
                    println!("The data is empty");
                }
            }

            // Move to the next argument
            start += end + 1;
            // Skip the null byte
            if start < total_size && args_data[start] == b'\0' {
                start += 1;
            }
        }

        println!("Debug: Found {} arguments", args.len());
        for (i, arg) in args.iter().enumerate() {
            println!("Debug: Arg {}: {}", i, arg);
        }

        if (self.0.event.flags & EVENT_DATA_ARGS) != 0 {
            println!("Debug: More arguments might be available but not captured");
        }

        args
    }

    fn get_hostname() -> String {
        uname()
            .map(|info| info.nodename().to_string_lossy().into_owned())
            .unwrap_or_else(|_| String::from("unknown"))
    }

    /// Get a username by UID.
    ///
    /// Internally calls `getpwuid_r(3)` to fetch user information from the system's user database.
    ///
    /// This function is thread-safe.
    ///
    /// # Returns
    /// - `Ok(Some(User))`: User found
    /// - `Ok(None)`: No user with given UID
    /// - `Err(_)`: Lookup error (e.g., I/O error, insufficient buffer)
    ///
    ///
    /// # Example
    /// ```
    /// use nix::unistd::{Uid, User};
    /// let root = User::from_uid(Uid::from_raw(0)).unwrap().unwrap();
    /// assert_eq!(root.name, "root");
    /// ```
    ///
    /// See `getpwuid_r(3)` man page for more details.
    fn get_username(&self) -> String {
        User::from_uid(nix::unistd::Uid::from_raw(self.0.event.uid))
            .map(|user_opt| {
                user_opt
                    .map(|user| user.name)
                    .unwrap_or_else(|| format!("uid:{}", self.0.event.uid))
            })
            .unwrap_or_else(|_| format!("uid:{}", self.0.event.uid))
    }
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    tracing_subscriber::fmt::init();

    // tracing::subscriber::set_global_default(stdout_subscriber)
    //     .expect("setting default subscriber failed");

    let _opt = Opt::parse();
    let mut agent_config = AgentConfig::default();

    let config = Config::builder()
        // TODO(wshel): fix this path to be a standard system location
        .add_source(File::with_name("/root/.scary/config.toml"))
        .build()?;

    let s3_config = S3LoggerConfig {
        region: config.get_string("s3_logger.region")?,
        bucket: config.get_string("s3_logger.bucket")?,
        prefix: config.get_string("s3_logger.prefix")?,
        access_key: config.get_string("s3_logger.access_key").ok(),
        secret_key: config.get_string("s3_logger.secret_key").ok(),
        batch_size: config.get_int("s3_logger.batch_size")? as usize,
        flush_interval: Duration::from_secs(config.get_int("s3_logger.flush_interval_secs")? as u64),
    };

    let s3_logger = S3Logger::new(s3_config).await?;

    let logger_config = LoggerConfig {
        logger: Arc::new(s3_logger) as Arc<dyn LoggerPlugin>,
    };

    agent_config.ip_blocking = config.get_bool("agent.ip_blocking")?;
    agent_config.logging = config.get_bool("agent.logging")?;

    println!("🐝 Welcome to the Scary eBPF! 🎃");

    loop {
        println!("\nPlease select an option:");
        println!("1. 🛡️ IP blocking");
        println!("2. 📊 Run the file integrity monitor");
        println!("3. 🚀 Run the process execution monitor");
        println!("4. 🚪 Exit");

        print!("Enter your choice: ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();

        match input.trim() {
            "1" => {
                println!("IP blocking is now enabled",);
            }
            "2" => {
                todo!();
            }
            "3" => {
                println!("🐝 Starting the process execution monitor... 🐝");
                run_proc_exec(&agent_config, &logger_config).await?;
            }
            "4" => {
                println!("🐝 Thanks for using Scary eBPF! Goodbye! 🐝");
                return Ok(());
            }
            _ => println!("Invalid option, please try again."),
        }
    }
}

async fn run_proc_exec(
    config: &AgentConfig,
    logger_config: &LoggerConfig,
) -> Result<(), anyhow::Error> {
    // Create a channel for sending events
    let (tx, rx) = mpsc::channel(1000);

    // Spawn a task to handle logging
    let logger = logger_config.logger.clone();
    let logging_handle = tokio::spawn(async move {
        handle_logging(rx, logger).await;
    });

    // Create a shutdown signal
    let shutdown = Arc::new(AtomicBool::new(false));

    // Vector to keep JoinHandles of per-CPU tasks
    let mut task_handles: Vec<JoinHandle<()>> = Vec::new();

    // Load the process execution eBPF program and create a 'static reference
    let ebpf_path = get_ebpf_path("scary-ebpf-process");
    let ebpf = Box::leak(Box::new(Ebpf::load_file(ebpf_path)?));

    // Initialize eBPF loggers
    if config.logging {
        if let Err(e) = EbpfLogger::init(ebpf) {
            warn!("failed to initialize eBPF logger for exec tracer: {}", e);
        }
    }

    // Load and attach programs
    EXEC_ENTER.load(ebpf)?;
    EXEC_EXIT.load(ebpf)?;

    // Load maps
    EVENTS_MAP.load(ebpf)?;

    info!("🐝 Scary eBPF Process Execution Monitor is running 🎃. Waiting for Ctrl-C...");

    let mut perf_array = PerfEventArray::try_from(ebpf.map_mut("EVENTS").unwrap())?;

    for cpu_id in
        online_cpus().map_err(|e| anyhow::anyhow!("Failed to get online CPUs: {:?}", e))?
    {
        let mut buf = perf_array.open(cpu_id, None)?;
        let tx = tx.clone();
        let shutdown = shutdown.clone();

        // Spawn per-CPU task using spawn_blocking
        let handle = tokio::task::spawn_blocking(move || {
            let mut buffers = vec![BytesMut::with_capacity(1024); 10];

            loop {
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }

                let events = match buf.read_events(&mut buffers) {
                    Ok(events) => events,
                    Err(e) => {
                        eprintln!("Error reading exec events: {}", e);
                        continue;
                    }
                };

                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    let ptr = buf.as_ptr() as *const EventData;
                    let data = unsafe { ptr.read_unaligned() };

                    // Process event and create EventJson...
                    let event_data = UserSpaceEventData(data);
                    let event_json = event_data.to_json();

                    // Serialize to pretty-printed JSON string
                    match serde_json::to_string_pretty(&event_json) {
                        Ok(json_str) => println!("{}", json_str),
                        Err(e) => eprintln!("Error serializing exec event to JSON: {}", e),
                    }

                    // Send the event to the logging task
                    // Since we're in a blocking context, use `blocking_send`
                    if let Err(e) = tx.blocking_send(event_json) {
                        error!("Error sending event to logging task: {}", e);
                    } else {
                        debug!("Sent event to logger...");
                    }
                }
            }

            // Drop tx to help close the channel when this task exits
            drop(tx);
        });

        task_handles.push(handle);
    }

    // Wait for Ctrl-C signal
    signal::ctrl_c().await?;
    info!("Exiting Process Execution Monitor...");

    // Signal shutdown to per-CPU tasks
    shutdown.store(true, Ordering::Relaxed);

    // Wait for per-CPU tasks to complete
    for handle in task_handles {
        handle.await?;
    }

    // Drop the main tx sender to close the channel
    drop(tx);

    // Wait for the logging task to complete
    logging_handle.await?;

    Ok(())
}

async fn handle_logging(mut rx: mpsc::Receiver<EventJson>, logger: Arc<dyn LoggerPlugin>) {
    while let Some(event_json) = rx.recv().await {
        println!("Debug: Received event for PID: {}", event_json.pid);
        println!("Debug: Command: {}", event_json.comm);
        println!("Debug: Arguments: {:?}", event_json.args);

        let json_value: Value = match serde_json::to_value(event_json) {
            Ok(value) => value,
            Err(e) => {
                error!("Error converting event to JSON value: {}", e);
                continue;
            }
        };

        // Log event using the logger plugin
        if let Err(e) = logger.log_event(json_value).await {
            error!("Error logging event: {}", e);
        }
    }

    // Ensure the remaining events are flushed when all events are received
    if let Err(e) = logger.flush().await {
        error!("Error flushing events on shutdown: {}", e);
    }
}
