//! Deterministic PE fixtures assembled from documented Delphi records, never executed.
#![allow(dead_code)]

pub struct Fixture {
    pub bytes: Vec<u8>,
    pub base: u64,
    pub ptr: usize,
    pub words: usize,
}

impl Fixture {
    pub fn new(wide: bool, modern: bool) -> Self {
        let base: u64 = if wide { 0x140001000 } else { 0x401000 };
        let ptr = if wide { 8 } else { 4 };
        let words = if wide {
            25
        } else if modern {
            22
        } else {
            19
        };
        let mut f = Self {
            bytes: vec![0; 0x2200],
            base,
            ptr,
            words,
        };
        f.bytes[..2].copy_from_slice(b"MZ");
        f.raw(0x3c, 0x80, 4);
        f.bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        f.raw(0x84, if wide { 0x8664 } else { 0x14c }, 2);
        f.raw(0x86, 1, 2);
        let optional_size = if wide { 240 } else { 224 };
        f.raw(0x94, optional_size, 2);
        f.raw(0x96, 0x22, 2);
        f.raw(0x98, if wide { 0x20b } else { 0x10b }, 2);
        for (off, value) in [
            (4, 0x2000),
            (16, 0x2400),
            (20, 0x1000),
            (32, 0x1000),
            (36, 0x200),
            (56, 0x3000),
            (60, 0x200),
        ] {
            f.raw(0x98 + off, value, 4);
        }
        f.raw(0x98 + if wide { 24 } else { 28 }, base - 0x1000, ptr);
        f.raw(0x98 + 68, 3, 2);
        let section = 0x98 + optional_size as usize;
        f.bytes[section..section + 4].copy_from_slice(b"CODE");
        for (off, value) in [
            (8, 0x2000),
            (12, 0x1000),
            (16, 0x2000),
            (20, 0x200),
            (36, 0x60000020),
        ] {
            f.raw(section + off, value, 4);
        }
        f.bytes[0x200..].fill(0xcc);
        // Primitive RTTI at the start of CODE, with bytes that resemble a prologue.
        f.number(0, base + ptr as u64, ptr);
        f.number(ptr, 1, 1);
        let data = f.string(ptr + 1, "Integer");
        f.number(data, 4, 1);
        f.number(data + 1, 0xe58955, 4);
        f.number(data + 5, 0x7fffffff, 4);
        f.class(0x100, "TBase", None);
        f.class(0x400, "TChild", Some(0x100));
        // Base's user virtual method is inherited by the child.
        f.pointer(0x100 + words * ptr, 0x1580);
        f.pointer(0x400 + words * ptr, 0x1580);
        // Published method and dynamic message handler.
        f.pointer(0x100 + 6 * ptr, 0x800);
        f.number(0x800, 1, 2);
        f.pointer(0x804, 0x1590);
        let end = f.string(0x804 + ptr, "OnClick");
        f.number(0x802, (end - 0x802) as u64, 2);
        f.pointer(0x100 + 7 * ptr, 0x900);
        f.number(0x900, 1, 2);
        f.number(0x902, 0x123, 2);
        f.pointer(0x904, 0x15a0);
        // Class RTTI with one property whose getter is a direct function VA.
        f.pointer(0x100 + 4 * ptr, 0xa00 + ptr);
        f.pointer(0xa00, 0xa00 + ptr);
        f.number(0xa00 + ptr, 7, 1);
        let data = f.string(0xa01 + ptr, "TBase");
        f.pointer(data, 0x100 + words * ptr);
        f.number(data + ptr, 0, ptr);
        f.number(data + 2 * ptr, 1, 2);
        let prop = f.string(data + 2 * ptr + 2, "TestUnit");
        f.number(prop, 1, 2);
        f.bytes[0x200 + prop + 2..0x200 + prop + 2 + 4 * ptr + 10].fill(0);
        f.pointer(prop + 2 + ptr, 0x15b0);
        f.string(prop + 2 + 4 * ptr + 10, "Value");
        // Real functions have no prologues and are reachable only through metadata.
        for offset in (0x1500..=0x15c0).step_by(0x10) {
            f.bytes[0x200 + offset..0x200 + offset + 6].copy_from_slice(&[0xb8, 42, 0, 0, 0, 0xc3]);
        }
        // The entry tries to call the RTTI prefix and then calls the named method.
        f.bytes[0x1600] = 0xe8;
        f.number(0x1401, (-0x1405i32) as u32 as u64, 4);
        f.bytes[0x1605] = 0xe8;
        f.number(0x1406, 0x1590 - 0x140a, 4);
        f.bytes[0x160a] = 0xc3;
        f
    }

    pub fn raw(&mut self, offset: usize, value: u64, width: usize) {
        self.bytes[offset..offset + width].copy_from_slice(&value.to_le_bytes()[..width]);
    }

    pub fn number(&mut self, offset: usize, value: u64, width: usize) {
        self.raw(0x200 + offset, value, width);
    }

    pub fn pointer(&mut self, offset: usize, target: usize) {
        self.number(offset, self.base + target as u64, self.ptr);
    }

    pub fn string(&mut self, offset: usize, text: &str) -> usize {
        self.number(offset, text.len() as u64, 1);
        self.bytes[0x201 + offset..0x201 + offset + text.len()].copy_from_slice(text.as_bytes());
        offset + 1 + text.len()
    }

    pub fn class(&mut self, header: usize, name: &str, parent: Option<usize>) {
        let p = self.ptr;
        let vmt = header + self.words * p;
        self.bytes[0x200 + header..0x200 + vmt + 2 * p].fill(0);
        self.pointer(header, vmt);
        self.pointer(header + 8 * p, header + 0x100);
        self.number(header + 9 * p, 32, p);
        if let Some(parent) = parent {
            self.pointer(header + 10 * p, parent);
        }
        for (i, slot) in (header + 11 * p..vmt).step_by(p).enumerate() {
            self.pointer(slot, 0x1500 + (i % 8) * 0x10);
        }
        self.string(header + 0x100, name);
    }
}
