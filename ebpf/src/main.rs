#![no_std]
#![no_main]
#![feature(generic_const_exprs)]

pub mod events;
mod maps;
mod programs;
pub mod stack;

#[allow(dead_code)]
#[cfg_attr(not(test), panic_handler)]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
