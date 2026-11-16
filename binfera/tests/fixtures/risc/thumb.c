extern unsigned arm_callee(unsigned);
__attribute__((noinline)) unsigned thumb_callee(unsigned x) { return arm_callee(x) ^ 3; }
