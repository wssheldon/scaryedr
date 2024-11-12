use std::process::Command;

use anyhow::Context as _;
use clap::Parser;

#[derive(Debug, Clone)]
pub enum Architecture {
    BpfEl,
    BpfEb,
}

impl Architecture {
    pub fn as_str(&self) -> &'static str {
        match self {
            Architecture::BpfEl => "bpfel-unknown-none",
            Architecture::BpfEb => "bpfeb-unknown-none",
        }
    }
}

impl std::str::FromStr for Architecture {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "bpfel-unknown-none" => Architecture::BpfEl,
            "bpfeb-unknown-none" => Architecture::BpfEb,
            _ => return Err("invalid target"),
        })
    }
}

impl std::fmt::Display for Architecture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Parser)]
pub struct Options {
    /// Set the endianness of the BPF target
    #[clap(default_value = "bpfel-unknown-none", long)]
    pub target: Architecture,
    /// Build the release target
    #[clap(long)]
    pub release: bool,
}

pub fn build_ebpf(opts: Options) -> Result<(), anyhow::Error> {
    let Options { target, release } = opts;

    let build_ebpf = |dir: &str| -> Result<(), anyhow::Error> {
        let mut cmd = Command::new("cargo");
        cmd.current_dir(dir).env_remove("RUSTUP_TOOLCHAIN").args([
            "build",
            "--target",
            target.as_str(),
        ]);

        if release {
            cmd.arg("--release");
        }

        let status = cmd
            .status()
            .context(format!("failed to build bpf program in {}", dir))?;

        anyhow::ensure!(
            status.success(),
            "failed to build bpf program in {}: {}",
            dir,
            status
        );
        Ok(())
    };

    build_ebpf("ebpf")?;
    build_ebpf("scary-ebpf-process")?;
    build_ebpf("scary-ebpf-net")?;
    build_ebpf("scary-ebpf-file")?;

    Ok(())
}
