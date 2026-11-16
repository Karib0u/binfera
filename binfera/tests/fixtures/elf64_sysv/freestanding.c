static long sys3(long n, long a, long b, long c) {
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "0"(n), "D"(a), "S"(b), "d"(c) : "rcx", "r11", "memory");
    return r;
}
__attribute__((noinline)) int sum_to(int n) {
    int total = 0;
    for (int i = 1; i <= n; i++) total += i * 2;
    return total;
}
__attribute__((noinline)) long write_hello(const char *s, long len) {
    return sys3(1, 1, (long)s, len);
}
__attribute__((noinline)) int classify(int x) {
    if (x < 0) return -1;
    if (x == 0) return 0;
    return sum_to(x) > 100 ? 2 : 1;
}
void _start(void) {
    write_hello("hello\n", 6);
    int c = classify(7);
    sys3(60, c, 0, 0);
    for (;;) {}
}
