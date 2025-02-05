use core::mem::replace;
use super::uart::Uart;

struct Peripherals {
  uart: Option<Uart>,
}

impl Peripherals {
  fn take_uart(&mut self) -> Uart {
    let p = replace(&mut self.uart, None);
    p.unwrap()
  }
}

static mut PERIPHERALS: Peripherals = Peripherals {
  uart: Some(Uart::new(0x10)),
};