use anyhow::{anyhow, Result};
use aya::Ebpf;
use std::path::PathBuf;

/// Represents an eBPF program to be loaded and attached.
pub struct ProgramBuilder {
    attach_point: &'static str,
    label: &'static str,
    function_name: &'static str,
    program_type: &'static str,
    policy: Option<&'static str>,
}

impl ProgramBuilder {
    /// Creates a new ProgramBuilder instance.
    ///
    /// # Arguments
    ///
    /// * `attach_point` - The point in the kernel where the program should be attached.
    /// * `label` - A label for the program.
    /// * `function_name` - The name of the function in the eBPF program to be loaded.
    /// * `program_type` - The type of the eBPF program (e.g., "tracepoint", "kprobe").
    pub fn new(
        attach_point: &'static str,
        label: &'static str,
        function_name: &'static str,
        program_type: &'static str,
    ) -> Self {
        Self {
            attach_point,
            label,
            function_name,
            program_type,
            policy: None,
        }
    }

    /// Sets the policy for the eBPF program.
    pub fn set_policy(mut self, policy: &'static str) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Loads and attaches the eBPF program.
    ///
    /// # Arguments
    ///
    /// * `ebpf` - A mutable reference to the Ebpf instance.
    ///
    /// # Returns
    ///
    /// A Result indicating success or failure.
    pub fn load(&self, ebpf: &mut Ebpf) -> Result<()> {
        match self.program_type {
            "tracepoint" => {
                let prog = ebpf
                    .program_mut(self.function_name)
                    .ok_or_else(|| anyhow!("Failed to get program {}", self.function_name))?
                    .try_into()?;
                let prog: &mut aya::programs::TracePoint = prog;
                prog.load()?;
                prog.attach(self.attach_point, self.label)?;
            }
            "kprobe" => {
                let prog = ebpf
                    .program_mut(self.function_name)
                    .ok_or_else(|| anyhow!("Failed to get program {}", self.function_name))?
                    .try_into()?;
                let prog: &mut aya::programs::KProbe = prog;
                prog.load()?;
                prog.attach(self.attach_point, 0)?;
            }
            _ => return Err(anyhow!("Unsupported program type: {}", self.program_type)),
        }
        Ok(())
    }
}

/// Represents an eBPF map to be loaded.
pub struct MapBuilder {
    name: &'static str,
}

impl MapBuilder {
    /// Creates a new MapBuilder instance.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the map.
    /// * `programs` - A vector of references to ProgramBuilder instances associated with this map.
    pub fn new(name: &'static str) -> Self {
        Self { name }
    }

    /// Loads the eBPF map.
    ///
    /// # Arguments
    ///
    /// * `ebpf` - A mutable reference to the Ebpf instance.
    ///
    /// # Returns
    ///
    /// A Result indicating success or failure.
    pub fn load(&self, ebpf: &mut Ebpf) -> Result<()> {
        let _map = ebpf
            .map_mut(self.name)
            .ok_or_else(|| anyhow!("Failed to get map {}", self.name))?;
        Ok(())
    }
}

/// Constructs the path to the eBPF program file.
///
/// # Arguments
///
/// * `program_name` - The name of the eBPF program file.
///
/// # Returns
///
/// A PathBuf representing the full path to the eBPF program file.
pub fn get_ebpf_path(program_name: &str) -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let ebpf_path = if cfg!(debug_assertions) {
        option_env!("CARGO_PKG_EBPF_DEBUG_PATH").unwrap_or("target/bpfel-unknown-none/debug")
    } else {
        option_env!("CARGO_PKG_EBPF_RELEASE_PATH").unwrap_or("target/bpfel-unknown-none/release")
    };

    PathBuf::from(manifest_dir)
        .parent()
        .expect("Failed to get parent directory")
        .join(ebpf_path)
        .join(program_name)
}
