// Compile-only fixture. The imported runtime is never executed.
extern "C" __declspec(dllimport) int may_throw(int);
extern "C" __declspec(dllimport) void cleanup(int);
struct Error { int code; };
struct Guard {
    int value;
    __declspec(noinline) ~Guard() { cleanup(value); }
};
extern "C" __declspec(dllexport) int nested_catches(int value) {
    Guard outer{value};
    try {
        Guard inner{value + 1};
        try {
            return may_throw(value);
        } catch (const Error &error) {
            return error.code;
        }
    } catch (int error) {
        return error + 10;
    } catch (...) {
        return -1;
    }
}
extern "C" __declspec(dllexport) int cleanup_only(int value) {
    Guard guard{value};
    return may_throw(value);
}
extern "C" __declspec(dllexport) int plain(int value) { return value + 1; }
extern "C" void *fixture_type_info_vftable[2] = {};
