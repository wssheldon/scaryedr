# scary

```bash
🐝 Starting the process execution monitor... 🐝

{
  "exec_id": "d8nPtgBlxzQhnjFFLh4/hs8MU8lcyaQ7hP5ePGNg7BcqHUjOk7s7o8ppksP0VrkajvcOyTAxbWnOe8ZEYO5xJQ==",
  "pid": 493853,
  "ppid": 493844,
  "tid": 493853,
  "uid": 0,
  "gid": 0,
  "comm": "cat",
  "cwd": "/root/Projects/scary",
  "binary": "/usr/bin/cat",
  "args": [
    "/root/.ssh/authorized_keys"
  ],
  "username": "root",
  "hostname": "ubuntu-32gb-hil-1",
  "timestamp": "2024-10-30T02:04:36.080166068+00:00"
}

2024-10-16T00:58:32.823465Z  INFO scary_logger_plugins::s3: Flushing 1 events to S3
```

## Prerequisites

1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag.

## Build Userspace

```bash
cargo build
```

## Build eBPF and Userspace

```bash
cargo xtask build
```

## Run

```bash
RUST_LOG=info cargo xtask run
```
