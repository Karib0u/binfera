#![no_std]

#[repr(C)]
pub struct Record { pub count: i32, pub total: i64 }

#[no_mangle]
#[inline(never)]
pub fn rust_update(record: &mut Record, amount: i32) -> i32 {
    record.count = record.count.wrapping_add(amount);
    record.count
}

#[no_mangle]
#[inline(never)]
pub fn rust_pair(value: i64) -> (i64, i64) { (value, value.wrapping_add(1)) }
