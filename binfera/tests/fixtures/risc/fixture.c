volatile unsigned result;

__attribute__((noinline)) unsigned mix(unsigned a, unsigned b) {
    return a > 7 ? (a ^ b) + 11 : a + b;
}

__attribute__((noinline)) unsigned invoke(unsigned a) {
    return mix(a, 3) + 5;
}

unsigned _start(void) {
    result = invoke(9);
    return result;
}
