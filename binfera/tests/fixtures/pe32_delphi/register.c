/* Delphi's `register` convention passes the first three arguments in EAX, EDX and ECX, the
   order gcc's regparm(3) uses, so this stands in for Delphi code. */
#define REGISTER __attribute__((regparm(3), noinline))
#include <windows.h>

REGISTER int scale(int value, int factor, int offset) {
    return value * factor + offset;
}
REGISTER int pick(int a, int b, int c) {
    return a < 0 ? scale(b, c, a) : scale(c, b, 7);
}
int WINAPI WinMainCRTStartup(void) {
    int r = pick(GetTickCount() & 7, 3, 4);
    ExitProcess(r);
    return 0;
}
