extern unsigned thumb_callee(unsigned);
volatile unsigned result;
__attribute__((noinline)) unsigned arm_callee(unsigned x) { return x + 7; }
unsigned _start(void) { result = thumb_callee(11); return result; }
