# scary

<p align="center">
  <img src="docs/assets/ebpf.png" width="20%" />
</p>

> [!WARNING]
> This project is actively in development and should not be used in any production capacity.

```bash
🍯 Initialized
🐝 Swarming...

{
  "event": {
    "process": {
      "comm": "cat",
      "gid": 493844,
      "pid": 493853,
      "ppid": 0,
      "start_time": 2821292941523322,
      "tid": 1028762,
      "uid": 0
    },
    "timestamp": 2821292941523091,
    "type": "file_access",
    "uuid": "7e34ec43df562e78-8c79be94651456f5"
  },
  "file": {
    "inode": 217558,
    "operation": "read",
    "path": "/root/.ssh/authorized_keys"
  }
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
