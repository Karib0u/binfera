int puts(const char *s);
unsigned long strlen(const char *s);
void *malloc(unsigned long n);
void *memcpy(void *d, const void *s, unsigned long n);
static long sys1(long n, long a) {
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "0"(n), "D"(a) : "rcx", "r11", "memory");
    return r;
}
__attribute__((noinline)) unsigned long copy_and_measure(const char *src) {
    unsigned long n = strlen(src);
    char *buf = malloc(n + 1);
    if (!buf) return 0;
    memcpy(buf, src, n + 1);
    puts(buf);
    return n;
}
void _start(void) {
    sys1(60, (long)copy_and_measure("binova"));
    for (;;) {}
}
