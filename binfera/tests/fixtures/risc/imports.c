extern int imported(int);
int call_import(int value) { return imported(value) + 1; }
const char *message(void) { return "risc fixture string"; }
