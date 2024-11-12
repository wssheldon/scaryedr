use crate::bindings::task_struct;
use crate::error::Error;
use aya_ebpf::helpers::{bpf_get_current_task, bpf_probe_read_kernel};

#[derive(Copy, Clone, Debug)]
pub struct TaskInfo {
    pub pid: u32,
    pub tgid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: [u8; 16],
    pub start_time: u64,
}

impl TaskInfo {
    pub unsafe fn from_current() -> Result<Self, Error> {
        Self::from_task_struct(bpf_get_current_task() as *const task_struct)
    }

    pub unsafe fn from_task_struct(task: *const task_struct) -> Result<Self, Error> {
        if task.is_null() {
            return Err(Error::InvalidTask);
        }

        let cred = bpf_probe_read_kernel(&(*task).cred).map_err(|e| Error::KernelRead(e))?;

        let real_parent =
            bpf_probe_read_kernel(&(*task).real_parent).map_err(|e| Error::KernelRead(e))?;

        let mut info = TaskInfo {
            pid: bpf_probe_read_kernel(&(*task).pid).map_err(|e| Error::KernelRead(e))? as u32,
            tgid: bpf_probe_read_kernel(&(*task).tgid).map_err(|e| Error::KernelRead(e))? as u32,
            ppid: bpf_probe_read_kernel(&(*real_parent).tgid).map_err(|e| Error::KernelRead(e))?
                as u32,
            uid: bpf_probe_read_kernel(&(*cred).uid.val).map_err(|e| Error::KernelRead(e))?,
            gid: bpf_probe_read_kernel(&(*cred).gid.val).map_err(|e| Error::KernelRead(e))?,
            comm: [0; 16],
            start_time: bpf_probe_read_kernel(&(*task).start_time)
                .map_err(|e| Error::KernelRead(e))?,
        };

        // Read comm - handling the i8 to u8 conversion
        let comm_ptr = &(*task).comm as *const [i8; 16];
        let comm: [i8; 16] = bpf_probe_read_kernel(comm_ptr).map_err(|e| Error::KernelRead(e))?;

        // Convert i8 array to u8 array
        for (i, &v) in comm.iter().enumerate() {
            info.comm[i] = v as u8;
        }

        Ok(info)
    }
}
