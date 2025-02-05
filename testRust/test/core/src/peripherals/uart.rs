use core::ptr;
use volatile_register::{RO, RW};

pub struct Uart {
  p: &'static mut UartRegisters 
}

#[repr(C)]
struct UartRegisters {
  pub csr: RW<u32>,
  pub rvr: RW<u32>,
  pub cvr: RW<u32>,
  pub calib: RO<u32>,
}

impl Uart {
  pub fn new(address: u32) -> Self {
    Uart { p: unsafe {&mut *(address as *mut UartRegisters)} }
  }

  fn read_speed(
    &self
  ) -> u32 {
    self.p.csr.read()
  }
}