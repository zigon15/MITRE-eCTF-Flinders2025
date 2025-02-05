#![no_main]
#![no_std]

use core::panic::PanicInfo;
use cortex_m_rt::entry;

mod peripherals;

#[entry]
fn main() -> ! {

    loop {}
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    // On a panic, loop forever
    loop {
        continue;
    }
}