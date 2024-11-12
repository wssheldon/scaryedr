pub mod connect;

use aya_ebpf::helpers::bpf_get_prandom_u32;
use core::mem::MaybeUninit;
use zerocopy::{FromBytes, IntoBytes};

#[derive(Clone, Copy, Debug)]
#[repr(u32)]
pub enum Type {
    Process = 0,
    Network = 1,
    File = 2,
}

#[derive(Clone, Copy, Debug, FromBytes, IntoBytes)]
#[repr(C, align(8))]
pub struct Uuid {
    pub data: [u64; 2],
}

impl Uuid {
    /// Generates a new UUID using BPF random number generator.
    ///
    /// Memory Generation Process:
    ///
    /// ```text
    /// 1. Create uninitialized UUID:
    /// +----------------+----------------+
    /// |    ????????    |    ????????    |
    /// +----------------+----------------+
    ///
    /// 2. Generate first u64:
    /// +--------------------------------+
    /// | bpf_random_32 | bpf_random_32  |
    /// +----------------+---------------+
    ///
    /// 3. Generate second u64:
    /// +----------------+----------------+
    /// |  First u64     |  Second u64    |
    /// +----------------+----------------+
    /// ```
    #[inline(always)]
    pub fn generate() -> Self {
        // create an uninitialized uuid on the stack
        let mut uuid = MaybeUninit::<Uuid>::uninit();
        let ptr = uuid.as_mut_ptr() as *mut u64;

        unsafe {
            // generate first u64 of UUID:
            //
            // 1. lower 32 bits using bpf_get_prandom_u32
            // 2. upper 32 bits using another bpf_get_prandom_u32
            // 3. combine them using bitwise OR after shifting upper bits
            // 4. convert to little-endian for consistent byte order
            *ptr = u64::from_le(
                // Lower 32 bits
                bpf_get_prandom_u32() as u64 |
                // Upper 32 bits (shifted left by 32)
                ((bpf_get_prandom_u32() as u64) << 32),
            );

            // generate second u64 of UUID using the same process
            // ptr.add(1) is safe because:
            //
            // 1. we know Uuid has space for 2 u64s
            // 2. the pointer remains within allocated bounds
            *ptr.add(1) =
                u64::from_le(bpf_get_prandom_u32() as u64 | ((bpf_get_prandom_u32() as u64) << 32));

            // Convert MaybeUninit<Uuid> into Uuid
            uuid.assume_init()
        }
    }
}

/// Event header with optimal memory layout for BPF processing.
///
/// Memory Layout (40 bytes total):
///
/// ```text
/// +----------------------------------------+
/// |                 UUID                   | 16 bytes
/// +----------------------------------------+
/// |              timestamp                 | 8 bytes
/// +----------------+-----------------------+
/// |      pid       |          tid          | 4 + 4 bytes
/// +----------------+-----------------------+
/// |   event_type   |         _pad          | 4 + 4 bytes
/// +----------------+-----------------------+
/// ^
/// aligned to 8-byte boundary
///
/// Field Alignment:
/// - uuid:       8-byte aligned (optimal for 64-bit access)
/// - timestamp:  8-byte aligned
/// - pid/tid:    4-byte aligned (packed together)
/// - type/pad:   4-byte aligned (packed together)
/// ```
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes)]
#[repr(C, align(8))]
pub struct Header {
    pub uuid: Uuid,      // 16 bytes, 8-byte aligned
    pub timestamp: u64,  // 8 bytes
    pub pid: u32,        // 4 bytes
    pub tid: u32,        // 4 bytes
    pub event_type: u32, // 4 bytes
    _pad: u32,           // 4 bytes padding
} // Total: 40 bytes, optimally aligned

/// Compile-time checks for layout optimization
const _: () = {
    assert!(core::mem::size_of::<Header>() % 8 == 0);
    assert!(core::mem::align_of::<Header>() >= 8);
};

#[derive(Clone)]
#[repr(C, align(8))]
pub struct Event<T>
where
    T: FromBytes + IntoBytes + Clone + 'static,
{
    pub header: Header,
    pub data: T,
}

impl<T> Event<T>
where
    T: FromBytes + IntoBytes + Clone + 'static,
{
    /// Creates a new event with process information.
    ///
    /// PID/TID Extraction:
    ///
    /// ```text
    /// pid_tgid (64 bits):
    /// +--------------------------------+--------------------------------+
    /// |              PID               |              TID               |
    /// +--------------------------------+--------------------------------+
    /// 63                              32                                0
    ///
    /// Extraction Process:
    /// 1. Mask PID:     pid_tgid & 0xFFFFFFFF00000000
    /// 2. Shift PID:    >> 32
    /// 3. Mask TID:     pid_tgid & 0x00000000FFFFFFFF
    /// ```
    #[inline]
    pub fn new(event_type: Type, data: T) -> Self {
        use aya_ebpf::helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns};

        let pid_tgid = bpf_get_current_pid_tgid();
        // Use const offsets for better BPF verifier handling
        const PID_SHIFT: u32 = 32;
        const PID_MASK: u64 = 0xFFFFFFFF00000000;

        Self {
            header: Header {
                uuid: Uuid::generate(),
                timestamp: unsafe { bpf_ktime_get_ns() },
                pid: ((pid_tgid & PID_MASK) >> PID_SHIFT) as u32,
                tid: pid_tgid as u32,
                event_type: event_type as u32,
                _pad: 0,
            },
            data,
        }
    }

    /// Converts the event to a byte slice for transmission.
    ///
    /// Memory Safety:
    ///
    /// ```text
    /// 1. Layout Guarantees:
    ///    - repr(C): Stable field ordering
    ///    - align(8): Proper alignment
    ///
    /// 2. Pointer Safety:
    ///    [Event<T>] -> [u8] conversion
    ///    +------------------+
    ///    | Header + Data    | -> [u8; size_of::<Event<T>>()]
    ///    +------------------+
    ///
    /// 3. Lifetime Safety:
    ///    - Returned slice lifetime tied to &self
    ///    - No mutable access during slice lifetime
    /// ```
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                (self as *const Self) as *const u8,
                core::mem::size_of::<Self>(),
            )
        }
    }
}
