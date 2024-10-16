# scary

```bash
🐝 Starting the process execution monitor... 🐝

{
  "pid": 162137,
  "ppid": 1175,
  "tid": 162137,
  "uid": 0,
  "gid": 0,
  "comm": "bash",
  "filename": "/usr/bin/cat",
  "args": [
    "cat",
    "/root/.ssh/authorized_keys"
  ],
  "username": "root",
  "hostname": "ubuntu-32gb-hil-1"
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
