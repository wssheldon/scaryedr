pub mod programs;

use crate::programs::{get_ebpf_path, MapBuilder, ProgramBuilder};
use aya::{
    include_bytes_aligned,
    maps::{HashMap, MapData, PerfEventArray},
    programs::{KProbe, SocketFilter, TracePoint, Xdp, XdpFlags},
    util::online_cpus,
    Ebpf,
};
use aya_log::EbpfLogger;
use base64::{engine::general_purpose, Engine as _};
use bytes::BytesMut;
use chrono::{DateTime, Utc};
use clap::Parser;
use config::{Config, File};
use ebpf::events::{
    connect::{ConnectData, ConnectEvent, IpAddr},
    Event, Type as EventType,
};
use log::{debug, error, info, warn};
use nix::sys::utsname::uname;
use nix::unistd::User;
use scary_ebpf_common::{EventData, EVENT_DATA_ARGS};
use scary_logger_plugins::s3::{S3Logger, S3LoggerConfig};
use scary_userspace_common::logger::config::LoggerConfig;
use scary_userspace_common::logger::LoggerPlugin;
use serde::{Deserialize, Serialize};
use serde_json;
use serde_json::{json, Value};
use std::collections::hash_map::DefaultHasher;
use std::convert::TryFrom;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::{
    fs,
    io::{self, Write},
    os::unix::fs::MetadataExt,
    path::Path,
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

    // static ref EVENTS_MAP: MapBuilder = MapBuilder::new("EVENTS");

    // static ref CONNECT_PROBE: ProgramBuilder = ProgramBuilder::new(
    //     "kprobe",
    //     "__sys_connect",
    //     "net_enter_sys_connect",
    //     "kprobe",
    // );

    // static ref CONNECT_RETPROBE: ProgramBuilder = ProgramBuilder::new(
    //     "kretprobe",
    //     "__sys_connect",
    //     "net_exit_sys_connect",
    //     "kretprobe",
    // );
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
struct NetworkEventJson {
    event_type: String,
    pid: u32,
    uid: u32,
    gid: u32,
    comm: String,
    socket_fd: i32,
    addr: Option<String>,  // For IPv4 address
    port: Option<u16>,     // For port number
    protocol: Option<u16>, // For protocol type
    username: String,
    hostname: String,
    timestamp: String,
}

// Create an enum to handle different event types
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
enum EventJsonType {
    Process(EventJson),
    Network(NetworkEventJson),
}

fn get_username(uid: u32) -> String {
    User::from_uid(nix::unistd::Uid::from_raw(uid))
        .map(|user_opt| {
            user_opt
                .map(|user| user.name)
                .unwrap_or_else(|| format!("uid:{}", uid))
        })
        .unwrap_or_else(|_| format!("uid:{}", uid))
}

fn get_hostname() -> String {
    uname()
        .map(|info| info.nodename().to_string_lossy().into_owned())
        .unwrap_or_else(|_| String::from("unknown"))
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

// fn convert_to_network_json(event: &Event) -> NetworkEventJson {
//     println!("Debug: Converting network event to JSON");
//     println!("Debug: Event type: {:?}", event.event_type);

//     let addr_string = unsafe {
//         match event.event_type {
//             EventType::NetworkConnect | EventType::NetworkBind => {
//                 let network_data = &event.payload.network;
//                 println!(
//                     "Debug: Network data - addr: {}, port: {}",
//                     network_data.addr, network_data.port
//                 );
//                 Some(format!(
//                     "{}.{}.{}.{}",
//                     (network_data.addr >> 24) & 0xff,
//                     (network_data.addr >> 16) & 0xff,
//                     (network_data.addr >> 8) & 0xff,
//                     network_data.addr & 0xff
//                 ))
//             }
//             _ => None,
//         }
//     };

//     let json = NetworkEventJson {
//         event_type: format!("{:#?}", event.event_type),
//         pid: event.task_info.pid,
//         uid: event.task_info.uid,
//         gid: event.task_info.gid,
//         comm: String::from_utf8_lossy(&event.task_info.comm)
//             .trim_end_matches('\0')
//             .to_string(),
//         socket_fd: unsafe { event.payload.network.sock_fd },
//         addr: addr_string,
//         port: unsafe { Some(event.payload.network.port) },
//         protocol: unsafe { Some(event.payload.network.proto) },
//         username: get_username(event.task_info.uid),
//         hostname: get_hostname(),
//         timestamp: format_timestamp(event.timestamp),
//     };

//     println!("Debug: Created network JSON event");
//     json
// }

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
    let (tx, rx) = mpsc::channel::<EventJsonType>(1000);

    // Spawn a task to handle logging
    let logger = logger_config.logger.clone();
    let logging_handle = tokio::spawn(async move {
        handle_logging(rx, logger).await;
    });

    // Create a shutdown signal
    let shutdown = Arc::new(AtomicBool::new(false));

    // Vector to keep JoinHandles of per-CPU tasks
    let mut task_handles: Vec<JoinHandle<()>> = Vec::new();

    // Load both process and network monitoring programs
    let ebpf_path = get_ebpf_path("ebpf");
    let proc_ebpf_path = get_ebpf_path("scary-ebpf-process");
    // let net_ebpf_path = get_ebpf_path("scary-ebpf-net");
    let file_ebpf_path = get_ebpf_path("scary-ebpf-file");

    let bpf = Box::leak(Box::new(Ebpf::load_file(ebpf_path)?));
    let proc_bpf = Box::leak(Box::new(Ebpf::load_file(proc_ebpf_path)?));
    // let net_bpf = Box::leak(Box::new(Ebpf::load_file(net_ebpf_path)?));
    let file_bpf = Box::leak(Box::new(Ebpf::load_file(file_ebpf_path)?));

    // Initialize eBPF loggers
    if config.logging {
        if let Err(e) = EbpfLogger::init(bpf) {
            warn!("failed to initialize eBPF logger: {}", e);
        }
        if let Err(e) = EbpfLogger::init(proc_bpf) {
            warn!("failed to initialize eBPF logger for exec tracer: {}", e);
        }
        // if let Err(e) = EbpfLogger::init(net_bpf) {
        //     warn!(
        //         "failed to initialize eBPF logger for network monitor: {}",
        //         e
        //     );
        // }
        if let Err(e) = EbpfLogger::init(file_bpf) {
            warn!("failed to initialize eBPF logger for file monitor: {}", e);
        }
    }

    // Load and attach process monitoring programs
    EXEC_ENTER.load(proc_bpf)?;
    EXEC_EXIT.load(proc_bpf)?;

    // Load and attach network monitoring programs
    // CONNECT_PROBE.load(bpf)?;
    // CONNECT_RETPROBE.load(bpf)?;

    // Function to load and attach a kprobe
    fn load_attach_kprobe(
        bpf: &mut Ebpf,
        prog_name: &str,
        attach_name: &str,
    ) -> Result<(), anyhow::Error> {
        let program: &mut KProbe = bpf
            .program_mut(prog_name)
            .ok_or_else(|| anyhow::anyhow!("Failed to find kprobe program {}", prog_name))?
            .try_into()?;
        program.load()?;
        program.attach(attach_name, 0)?;
        info!(
            "Loaded and attached kprobe {} -> {}",
            prog_name, attach_name
        );
        Ok(())
    }

    // Load and attach all network probes
    // let kprobe_mappings = [
    //     ("net_enter_sys_connect", "__sys_connect"),
    //     ("net_enter_sys_listen", "__sys_listen"),
    //     ("net_enter_sys_bind", "__sys_bind"),
    //     ("net_enter_sys_accept", "__sys_accept4"),
    //     ("net_enter_sys_sendto", "__sys_sendto"),
    //     ("net_enter_sys_recvfrom", "__sys_recvfrom"),
    //     ("net_exit_sys_bind", "__sys_bind"),
    //     ("net_exit_sys_connect", "__sys_connect"),
    //     ("net_exit_sys_listen", "__sys_listen"),
    // ];

    // for (prog_name, attach_name) in kprobe_mappings.iter() {
    //     if let Err(e) = load_attach_kprobe(net_bpf, prog_name, attach_name) {
    //         warn!("Failed to load/attach kprobe {}: {}", prog_name, e);
    //     }
    // }

    let program: &mut KProbe = file_bpf
        .program_mut("monitor_file_open")
        .unwrap()
        .try_into()?;
    program.load()?;
    program.attach("security_file_open", 0)?;

    // Open the BPF map
    let map = file_bpf
        .map_mut("WATCHED_INODES")
        .ok_or_else(|| anyhow::anyhow!("Failed to find WATCHED_INODES map"))?;

    let mut inode_map: HashMap<_, u64, u8> = HashMap::try_from(map)?;

    // List of files to monitor
    let files_to_monitor = vec!["/root/.ssh/authorized_keys", "/root/.bash_history"];

    // Populate the inode map
    for file_path in files_to_monitor {
        let metadata = fs::metadata(file_path)?;
        let inode = metadata.ino();
        inode_map.insert(inode, 0, 0)?;
        println!("Monitoring file: {} (inode {})", file_path, inode);
    }

    // Set up perf arrays for both process and network events
    let mut proc_perf_array = PerfEventArray::try_from(proc_bpf.map_mut("EVENTS").unwrap())?;

    let connect_program: &mut KProbe = bpf
        .program_mut("net_enter_sys_connect")
        .unwrap()
        .try_into()?;
    connect_program.load()?;
    connect_program.attach("__sys_connect", 0)?;
    let mut net_perf_array = match bpf.map_mut("SCARY_EVENTS") {
        Some(map) => match PerfEventArray::try_from(map) {
            Ok(array) => array,
            Err(e) => {
                error!("Failed to create network perf array: {}", e);
                return Err(anyhow::anyhow!("Failed to create network perf array"));
            }
        },
        None => {
            error!("Failed to find SCARY_EVENTS map in main BPF program");
            return Err(anyhow::anyhow!("Failed to find SCARY_EVENTS map"));
        }
    };
    info!("🐝 Scary eBPF Monitor is running 🎃. Waiting for Ctrl-C...");

    for cpu_id in
        online_cpus().map_err(|e| anyhow::anyhow!("Failed to get online CPUs: {:?}", e))?
    {
        let mut proc_buf = proc_perf_array.open(cpu_id, None)?;
        let mut net_buf = net_perf_array.open(cpu_id, None)?;
        let tx = tx.clone();
        let shutdown = shutdown.clone();

        // Spawn per-CPU task using spawn_blocking
        let handle = tokio::task::spawn_blocking(move || {
            let mut buffers = vec![BytesMut::with_capacity(1024); 10];

            loop {
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }

                // Read process events
                // if let Ok(events) = proc_buf.read_events(&mut buffers) {
                //     for i in 0..events.read {
                //         let buf = &mut buffers[i];
                //         // Read as EventData instead of Event
                //         let ptr = buf.as_ptr() as *const EventData;
                //         let event_data = unsafe { ptr.read_unaligned() };

                //         println!("Debug: Received process event");

                //         // Create UserSpaceEventData and convert to JSON
                //         let user_space_event = UserSpaceEventData(event_data);
                //         let event_json = EventJsonType::Process(user_space_event.to_json());

                //         // Pretty print for debugging
                //         if let Ok(json_str) = serde_json::to_string_pretty(&event_json) {
                //             println!("Process Event JSON:\n{}", json_str);
                //         }

                //         if let Err(e) = tx.blocking_send(event_json) {
                //             error!("Error sending process event to logging task: {}", e);
                //         }
                //     }
                // }

                // Read network events
                if let Ok(events) = net_buf.read_events(&mut buffers) {
                    for i in 0..events.read {
                        let buf = &mut buffers[i];
                        let ptr = buf.as_ptr() as *const ConnectEvent;
                        let event = unsafe { ptr.read_unaligned() };

                        // Safely copy packed fields to local variables
                        let uuid_data = unsafe {
                            [
                                ptr::read_unaligned(&event.header.uuid.data[0]),
                                ptr::read_unaligned(&event.header.uuid.data[1]),
                            ]
                        };

                        let src_addr = unsafe {
                            [
                                ptr::read_unaligned(&event.data.src_addr.addr[0]),
                                ptr::read_unaligned(&event.data.src_addr.addr[1]),
                                ptr::read_unaligned(&event.data.src_addr.addr[2]),
                                ptr::read_unaligned(&event.data.src_addr.addr[3]),
                            ]
                        };

                        let dst_addr = unsafe {
                            [
                                ptr::read_unaligned(&event.data.dst_addr.addr[0]),
                                ptr::read_unaligned(&event.data.dst_addr.addr[1]),
                                ptr::read_unaligned(&event.data.dst_addr.addr[2]),
                                ptr::read_unaligned(&event.data.dst_addr.addr[3]),
                            ]
                        };

                        // Get other values
                        let socket_fd = unsafe { ptr::read_unaligned(&event.data.sock_fd) };
                        let proto = unsafe { ptr::read_unaligned(&event.data.proto) };
                        let src_port = unsafe { ptr::read_unaligned(&event.data.src_port) };
                        let dst_port = unsafe { ptr::read_unaligned(&event.data.dst_port) };
                        let connected = unsafe { ptr::read_unaligned(&event.data.connected) };
                        let pid = unsafe { ptr::read_unaligned(&event.header.pid) };
                        let tid = unsafe { ptr::read_unaligned(&event.header.tid) };
                        let timestamp = unsafe { ptr::read_unaligned(&event.header.timestamp) };

                        // Convert event to JSON using local variables
                        let json_value = json!({
                            "event": {
                                "uuid": format!("{:x}-{:x}", uuid_data[0], uuid_data[1]),
                                "type": "connect",
                                "timestamp": timestamp,
                                "process": {
                                    "pid": pid,
                                    "tid": tid
                                }
                            },
                            "connection": {
                                "socket": {
                                    "fd": socket_fd,
                                    "protocol": proto
                                },
                                "source": {
                                    "address": format!("{}.{}.{}.{}",
                                        src_addr[0], src_addr[1], src_addr[2], src_addr[3]
                                    ),
                                    "port": src_port
                                },
                                "destination": {
                                    "address": format!("{}.{}.{}.{}",
                                        dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]
                                    ),
                                    "port": dst_port
                                },
                                "state": if connected == 1 { "connected" } else { "connecting" }
                            }
                        });

                        // Pretty print the JSON
                        println!("{}", serde_json::to_string_pretty(&json_value).unwrap());
                    }
                }
            }

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

async fn handle_logging(mut rx: mpsc::Receiver<EventJsonType>, logger: Arc<dyn LoggerPlugin>) {
    while let Some(event_json) = rx.recv().await {
        // Pretty print the received event
        if let Ok(json_str) = serde_json::to_string_pretty(&event_json) {
            println!("Logging Event:\n{}", json_str);
        }
        match &event_json {
            EventJsonType::Process(process_event) => {
                println!(
                    "Debug: Received process event for PID: {}",
                    process_event.pid
                );
            }
            EventJsonType::Network(network_event) => {
                println!(
                    "Debug: Received network event for PID: {}",
                    network_event.pid
                );
                println!("Debug: Command: {}", network_event.comm);
                if let Some(addr) = &network_event.addr {
                    println!("Debug: Address: {}", addr);
                }
                if let Some(port) = network_event.port {
                    println!("Debug: Port: {}", port);
                }
            }
        }

        let json_value: Value = match serde_json::to_value(event_json) {
            Ok(value) => value,
            Err(e) => {
                error!("Error converting event to JSON value: {}", e);
                continue;
            }
        };

        if let Err(e) = logger.log_event(json_value).await {
            error!("Error logging event: {}", e);
        }
    }

    if let Err(e) = logger.flush().await {
        error!("Error flushing events on shutdown: {}", e);
    }
}
