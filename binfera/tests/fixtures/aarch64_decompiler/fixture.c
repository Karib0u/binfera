/* Freestanding fixtures, only analyzed, never executed. */
typedef __SIZE_TYPE__ size_t;
#ifdef _WIN32
__declspec(dllimport) unsigned long GetTickCount(void);
__declspec(dllimport) void ExitProcess(unsigned int code);
#define EXPORT __declspec(dllexport)
#else
int puts(const char *s);
size_t strlen(const char *s);
#define EXPORT
#endif
EXPORT __attribute__((noinline)) int arithmetic(int x, int y) { return x * 3 + y; }
EXPORT __attribute__((noinline)) double floating(double x, double y) { return x * 2.0 + y; }
EXPORT __attribute__((noinline)) long ninth(long a, long b, long c, long d, long e,
                                           long f, long g, long h, long i) {
    return a + b + c + d + e + f + g + h + i;
}
EXPORT __attribute__((noinline)) int caller(int x) { return arithmetic(x, 7) + 9; }
#ifndef _WIN32
static const char greeting[] = "arm64 relocation";
const char *message = greeting;
const char *exported_message = greeting;
const char **message_address = &exported_message;
EXPORT __attribute__((noinline)) size_t imported(const char *s) {
    puts(s);
    return strlen(s);
}
EXPORT __attribute__((noinline)) int relocated(void) { return puts(message); }
EXPORT __attribute__((noinline)) long raw_syscall(void) {
    register long n __asm__("x8") = 172;
    register long result __asm__("x0");
    __asm__ volatile("svc #0" : "=r"(result) : "r"(n) : "memory");
    return result;
}
void _start(void) { imported(message); caller(4); for (;;) {} }
#else
EXPORT __attribute__((noinline)) unsigned long imported(void) { return GetTickCount(); }
void entry_point(void) { ExitProcess(caller((int)imported())); }
#endif
