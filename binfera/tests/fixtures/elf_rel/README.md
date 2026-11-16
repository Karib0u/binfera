# Relocatable ELF fixtures

`module.c` is trusted test source. The checked-in objects exercise zero-offset function symbols, BSS, read-only data, external calls and relocations on both x86 widths. They are analyzed only and do not require a kernel or module loader.

Rebuild from this directory with clang:

```sh
clang --target=x86_64-linux-gnu -O1 -fno-builtin -fno-pic -fno-stack-protector -c module.c -o module64.elf
clang --target=i686-linux-gnu -O1 -fno-builtin -fno-pic -fno-stack-protector -c module.c -o module32.elf
```

The `.elf` extension avoids the repository's object-file ignore rule; these are ET_REL objects, not linked executables.
