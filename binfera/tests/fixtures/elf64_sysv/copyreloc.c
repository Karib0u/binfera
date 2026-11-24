/* Reads two library variables. Built without PIC, so the linker copies them into this file's .bss. */
extern void *stdout;
extern int optind;
static long sys1(long n, long a) {
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "0"(n), "D"(a) : "rcx", "r11", "memory");
    return r;
}
void _start(void) {
    sys1(60, (long)stdout + optind);
    for (;;) {}
}
