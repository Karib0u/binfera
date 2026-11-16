#![no_std]
#![no_main]

use core::panic::PanicInfo;

extern "C" {
    fn consume(data: *const u8, length: usize) -> usize;
}

#[no_mangle]
pub static MESSAGES: [&str; 2] = ["first", "second"];

#[inline(never)]
pub fn print_message() -> usize {
    // Inline pointer/length arguments with no NUL terminator and multi-byte UTF-8.
    unsafe { consume("hello, café".as_ptr(), "hello, café".len()) }
}

#[inline(never)]
pub fn print_first() -> usize {
    let message = MESSAGES[0];
    unsafe { consume(message.as_ptr(), message.len()) }
}

#[inline(never)]
pub fn print_second() -> usize {
    let message = MESSAGES[1];
    unsafe { consume(message.as_ptr(), message.len()) }
}

#[inline(never)]
pub fn read_message(index: usize) -> usize {
    // The fixture is only decompiled. Avoid linking core's panic implementation into it.
    let message = unsafe { MESSAGES.get_unchecked(index) };
    unsafe { consume(message.as_ptr(), message.len()) }
}

#[no_mangle]
pub extern "C" fn _start(index: usize) -> usize {
    print_message() + read_message(index)
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    loop { core::hint::spin_loop(); }
}
