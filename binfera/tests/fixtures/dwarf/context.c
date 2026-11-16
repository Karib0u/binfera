struct Record { int count; long long total; struct Record *next; };
__attribute__((noinline)) int update(struct Record *record, int amount) {
    int adjusted = amount + 3;
    record->count += adjusted;
    record->total += record->count;
    return record->count;
}
__attribute__((noinline)) int call_update(int value) {
    struct Record record;
    record.count = value; record.total = 10; record.next = 0;
    return update(&record, 7);
}
void _start(void) { call_update(5); }
