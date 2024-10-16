use aya::{
    include_bytes_aligned,
    maps::PerfEventArray,
    programs::{Lsm, TracePoint},
    util::online_cpus,
    Btf, Ebpf,
};
use aya_log::EbpfLogger;
use bytes::BytesMut;
use clap::Parser;
use config::{Config, File};
use log::{info, warn};
use nix::unistd::User;
use scary_logger_plugins::s3::{S3Logger, S3LoggerConfig};
use scary_userspace_common::logger::config::LoggerConfig;
use scary_userspace_common::logger::LoggerPlugin;
use serde::{Deserialize, Serialize};
use serde_json;
use serde_json::Value;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::{
    io::{self, Write},
    str,
};
use tokio::signal;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

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

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct Event {
    pid: u32,
    tid: u32,
    uid: u32,
    gid: u32,
    ppid: u32,
    filename: [u8; 256],
    comm: [u8; 16],
    filename_read_result: i64,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct EventData {
    event: Event,
    args: [[u8; 64]; 10], // Updated to match the eBPF struct (MAX_ARGS = 10)
    args_read_result: i32,
}

// Define structs for JSON serialization
#[derive(Debug, Serialize, Deserialize)]
struct EventJson {
    pid: u32,
    ppid: u32,
    tid: u32,
    uid: u32,
    gid: u32,
    comm: String,
    filename: String,
    args: Vec<String>,
    username: String,
}

impl EventData {
    fn to_json(&self) -> EventJson {
        EventJson {
            pid: self.event.pid,
            ppid: self.event.ppid,
            tid: self.event.tid,
            uid: self.event.uid,
            gid: self.event.gid,
            comm: self.get_comm(),
            filename: self.get_filename(),
            args: self.get_args(),
            username: self.get_username(),
        }
    }

    fn get_comm(&self) -> String {
        str::from_utf8(&self.event.comm)
            .map(|s| s.trim_end_matches('\0').to_string())
            .unwrap_or_else(|_| "<invalid utf8>".to_string())
    }

    fn get_filename(&self) -> String {
        str::from_utf8(&self.event.filename)
            .map(|s| s.trim_end_matches('\0').to_string())
            .unwrap_or_else(|_| "<invalid utf8>".to_string())
    }

    fn get_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        let mut total_len = 0;
        for arg in &self.args {
            if total_len >= self.args_read_result as usize {
                break;
            }
            if let Ok(s) = str::from_utf8(arg) {
                let trimmed = s.trim_end_matches('\0');
                if trimmed.is_empty() {
                    break;
                }
                total_len += trimmed.len() + 1; // +1 for null terminator
                args.push(trimmed.to_string());
            } else {
                break;
            }
        }
        args
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
        User::from_uid(nix::unistd::Uid::from_raw(self.event.uid))
            .map(|user_opt| {
                user_opt
                    .map(|user| user.name)
                    .unwrap_or_else(|| format!("uid:{}", self.event.uid))
            })
            .unwrap_or_else(|_| format!("uid:{}", self.event.uid))
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
                run_fim(&agent_config).await?;
            }
            "3" => {
                println!("🐝 Starting the process execution monitor... 🐝");
                run_proc_exec(&agent_config, &logger_config).await?;
            }
            "4" => {
                println!("🐝 Thanks for using Scary eBPF! Goodbye! 🐝");
                // Before exiting, signal the background flush task to shutdown
                // s3_logger.trigger_shutdown();
                return Ok(());
            }
            _ => println!("Invalid option, please try again."),
        }
    }
}

async fn run_fim(_config: &AgentConfig) -> Result<(), anyhow::Error> {
    // Load the process execution eBPF program
    let fim_ebpf = Box::leak(Box::new(Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/scary-ebpf-file-lsm"
    ))?));

    if let Err(e) = EbpfLogger::init(fim_ebpf) {
        warn!("failed to initialize eBPF logger for exec tracer: {}", e);
    }

    // Attach FIM program (LSM)
    let fim_program: &mut Lsm = fim_ebpf
        .program_mut("monitor_file_open")
        .unwrap()
        .try_into()?;

    let btf = Btf::from_sys_fs()?;
    fim_program.load("file_open", &btf)?;
    fim_program.attach()?;

    info!("🐝 Scary eBPF FIM is running 🎃. Waiting for Ctrl-C...");

    let mut fim_perf_array = PerfEventArray::try_from(fim_ebpf.map_mut("EVENTS").unwrap())?;

    for cpu_id in
        online_cpus().map_err(|e| anyhow::anyhow!("Failed to get online CPUs: {:?}", e))?
    {
        let mut buf = fim_perf_array.open(cpu_id, None)?;

        tokio::spawn(async move {
            let mut buffers = vec![BytesMut::with_capacity(1024); 10];

            loop {
                let events = match buf.read_events(&mut buffers) {
                    Ok(events) => events,
                    Err(e) => {
                        eprintln!("Error reading FIM events: {}", e);
                        continue;
                    }
                };

                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    let ptr = buf.as_ptr() as *const Event;
                    let data = unsafe { ptr.read_unaligned() };

                    // Convert comm to String
                    let comm = match str::from_utf8(&data.comm) {
                        Ok(s) => s.trim_end_matches('\0').to_string(),
                        Err(_) => "<invalid utf8>".to_string(),
                    };

                    // Create the JSON object for the FIM event
                    let event_json = EventJson {
                        pid: data.pid,
                        ppid: 0,
                        tid: 0,
                        uid: data.uid,
                        gid: data.gid,
                        comm,
                        filename: format!("inode"),
                        args: vec![],
                        username: User::from_uid(nix::unistd::Uid::from_raw(data.uid))
                            .map(|user_opt| {
                                user_opt
                                    .map(|user| user.name)
                                    .unwrap_or_else(|| format!("uid:{}", data.uid))
                            })
                            .unwrap_or_else(|_| format!("uid:{}", data.uid)),
                    };

                    // Serialize to JSON string and print
                    match serde_json::to_string(&event_json) {
                        Ok(json_str) => println!("{}", json_str),
                        Err(e) => eprintln!("Error serializing FIM event to JSON: {}", e),
                    }
                }
            }
        });
    }

    signal::ctrl_c().await?;
    info!("Exiting FIM...");

    Ok(())
}

async fn run_proc_exec(
    config: &AgentConfig,
    logger_config: &LoggerConfig,
) -> Result<(), anyhow::Error> {
    // Create a channel for sending events
    let (tx, rx) = mpsc::channel(1000); // Adjust buffer size as needed

    // Spawn a task to handle logging
    let logger = logger_config.logger.clone();
    let logging_handle = tokio::spawn(async move {
        handle_logging(rx, logger).await;
    });

    // Create a shutdown signal
    let shutdown = Arc::new(AtomicBool::new(false));

    // Vector to keep JoinHandles of per-CPU tasks
    let mut task_handles: Vec<JoinHandle<()>> = Vec::new();

    // Load the process execution eBPF program
    let ebpf = Box::leak(Box::new(Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/scary-ebpf-process"
    ))?));

    // Initialize eBPF loggers
    if config.logging {
        if let Err(e) = EbpfLogger::init(ebpf) {
            warn!("failed to initialize eBPF logger for exec tracer: {}", e);
        }
    }

    // Attach process execution tracer
    let exec_trace: &mut TracePoint = ebpf.program_mut("handle_exec").unwrap().try_into()?;
    exec_trace.load()?;
    exec_trace.attach("syscalls", "sys_enter_execve")?;

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
                    let event_json = data.to_json();

                    // Serialize to JSON string
                    match serde_json::to_string(&event_json) {
                        Ok(json_str) => println!("{}", json_str),
                        Err(e) => eprintln!("Error serializing exec event to JSON: {}", e),
                    }

                    // Send the event to the logging task
                    // Since we're in a blocking context, use `blocking_send`
                    if let Err(e) = tx.blocking_send(event_json) {
                        eprintln!("Error sending event to logging task: {}", e);
                    } else {
                        println!("Sent event to logger...");
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
        println!("Received event for logging..."); // Added for debugging
        let json_value: Value = match serde_json::to_value(event_json) {
            Ok(value) => value,
            Err(e) => {
                eprintln!("Error converting event to JSON value: {}", e);
                continue;
            }
        };

        // Log event using the logger plugin
        if let Err(e) = logger.log_event(json_value).await {
            eprintln!("Error logging event: {}", e);
        }
    }

    // Ensure the remaining events are flushed when all events are received
    if let Err(e) = logger.flush().await {
        eprintln!("Error flushing events on shutdown: {}", e);
    }
}
