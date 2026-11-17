/* Trivial fixture source for binfera's AArch64 PE corpus (V3-0 task 4).
 * Same `-nostdlib`/custom-entry-point rationale as fixture_exe.c -- see that
 * file's comment. This one produces the exports side of the pair. */
__declspec(dllexport) int ExportedAdd(int a, int b) {
    return a + b;
}

__declspec(dllexport) int ExportedMul(int a, int b) {
    return a * b;
}

int dll_entry(void) {
    return 1;
}
