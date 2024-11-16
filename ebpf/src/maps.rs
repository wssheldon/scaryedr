//! Memory-safe eBPF event handling with zero-copy data transfer
//!
//! This module provides a simplified wrapper around eBPF PerfEventByteArray
//! that works within eBPF constraints while avoiding undefined behavior
//! from static mut references.
//!
//!  Zero-copy data flow:
//! ┌─────────────────────┐    No Copy    ┌──────────────────┐
//! │ Event<T> in BPF                   │ ────────────> │      Raw bytes in    │
//! │ - Header                          │               │             PerfEventArray   │
//! │ - Data (type T)                   │               │                              │
//! └─────────────────────┘               └──────────────────┘
//!                                              │
//!                                              │ No Copy
//!                                              ▼
//!                                      ┌──────────────────┐
//!                                      │ Userspace Event              │
//!                                      │ reconstruction               │
//!                                      └──────────────────┘
//!

use super::events::Event;
use aya_ebpf::{macros::map, maps::PerfEventByteArray, EbpfContext};

#[map(name = "SCARY_EVENTS")]
pub static mut EVENTS: PerfEventByteArray = PerfEventByteArray::new(0);

/// Zero-copy transfer of event data to the kernel.
///
/// # Safety
/// - Event data must be properly aligned and sized
/// - Caller must ensure no other references to EVENTS exist
#[inline(always)]
pub fn send<C, T>(ctx: &C, event: &Event<T>)
where
    C: EbpfContext,
    T: Clone,
{
    // Get a raw pointer using &raw mut to avoid reference creation
    let events_ptr = &raw mut EVENTS;

    // Use the raw pointer directly
    unsafe { (*events_ptr).output(ctx, event.as_bytes(), 0) };
}
