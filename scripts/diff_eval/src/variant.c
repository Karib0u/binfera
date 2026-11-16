/* A small program with enough kinds of function to exercise matching: leaf arithmetic, table
 * lookups, string handling, callers of callers and near-duplicates. `VARIANT` is the patch. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef VARIANT
#define KEY 0x5a17c3e1u
#define SERVER "update.example.net"
#else
#define KEY 0x13c6ef37u
#define SERVER "cdn.example.org"
#endif

struct record {
    unsigned id;
    char name[24];
    struct record *next;
};

__attribute__((noinline)) unsigned checksum(const unsigned char *data, size_t size) {
    unsigned sum = 0x811c9dc5u;
    for (size_t i = 0; i < size; i++) {
        sum = (sum ^ data[i]) * 16777619u;
    }
    return sum;
}

__attribute__((noinline)) void rc4_init(unsigned char *state, const unsigned char *key, size_t size) {
    for (int i = 0; i < 256; i++) {
        state[i] = (unsigned char)i;
    }
    unsigned j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + state[i] + key[i % size]) & 0xff;
        unsigned char swap = state[i];
        state[i] = state[j];
        state[j] = swap;
    }
}

__attribute__((noinline)) void rc4_apply(unsigned char *state, unsigned char *data, size_t size) {
    unsigned i = 0, j = 0;
    for (size_t at = 0; at < size; at++) {
        i = (i + 1) & 0xff;
        j = (j + state[i]) & 0xff;
        unsigned char swap = state[i];
        state[i] = state[j];
        state[j] = swap;
        data[at] ^= state[(state[i] + state[j]) & 0xff];
    }
}

__attribute__((noinline)) unsigned derive_key(const char *seed) {
    unsigned value = checksum((const unsigned char *)seed, strlen(seed));
    return value ^ KEY;
}

__attribute__((noinline)) const char *server_name(void) {
    return SERVER;
}

__attribute__((noinline)) int parse_port(const char *text) {
    int port = 0;
    while (*text >= '0' && *text <= '9') {
        port = port * 10 + (*text++ - '0');
    }
#ifdef VARIANT
    if (port > 49151) {
        return 8443;
    }
#endif
    return port > 0 && port < 65536 ? port : 443;
}

__attribute__((noinline)) int classify(int code) {
    switch (code) {
    case 0: return 11;
    case 1: return 23;
    case 2: return 37;
    case 3: return 41;
    case 5: return 59;
    case 8: return 67;
    case 13: return 71;
    default: return -1;
    }
}

__attribute__((noinline)) struct record *record_new(unsigned id, const char *name) {
    struct record *made = malloc(sizeof *made);
    if (!made) {
        abort();
    }
    made->id = id;
    strncpy(made->name, name, sizeof made->name - 1);
    made->name[sizeof made->name - 1] = 0;
    made->next = NULL;
    return made;
}

__attribute__((noinline)) struct record *record_find(struct record *list, unsigned id) {
    for (; list; list = list->next) {
        if (list->id == id) {
            return list;
        }
    }
    return NULL;
}

__attribute__((noinline)) void record_free(struct record *list) {
    while (list) {
        struct record *next = list->next;
        free(list);
        list = next;
    }
}

__attribute__((noinline)) void log_line(const char *what, int value) {
    printf("[%s] %d\n", what, value);
}

__attribute__((noinline)) void log_error(const char *what, int value) {
    fprintf(stderr, "error: %s (%d)\n", what, value);
}

__attribute__((noinline)) long sum_table(const int *table, size_t size) {
    long total = 0;
    for (size_t i = 0; i < size; i++) {
        total += table[i];
    }
    return total;
}

__attribute__((noinline)) long max_table(const int *table, size_t size) {
    long best = table[0];
    for (size_t i = 1; i < size; i++) {
        if (table[i] > best) {
            best = table[i];
        }
    }
    return best;
}

__attribute__((noinline)) int connect_stub(const char *host, int port) {
    log_line(host, port);
    return (int)(checksum((const unsigned char *)host, strlen(host)) % 7);
}

__attribute__((noinline)) int beacon(const char *seed) {
    unsigned key = derive_key(seed);
    unsigned char state[256];
    unsigned char message[32] = "ping";
    rc4_init(state, (unsigned char *)&key, sizeof key);
    rc4_apply(state, message, sizeof message);
    int link = connect_stub(server_name(), parse_port("8080"));
#ifdef VARIANT
    if (link == 3) {
        log_error("retry", link);
        link = connect_stub("fallback.example.net", 8443);
    }
#endif
    if (link < 0) {
        log_error("connect", link);
    }
    return classify(link) + message[0];
}

__attribute__((noinline)) int build_list(void) {
    struct record *head = NULL;
    static const char *const names[] = {"alpha", "bravo", "charlie", "delta"};
    for (unsigned i = 0; i < 4; i++) {
        struct record *item = record_new(i * 3, names[i]);
        item->next = head;
        head = item;
    }
    struct record *found = record_find(head, 6);
    int result = found ? (int)strlen(found->name) : 0;
    record_free(head);
    return result;
}

#ifdef VARIANT
__attribute__((noinline)) int persist(const char *path) {
    FILE *file = fopen(path, "ab");
    if (!file) {
        log_error("persist", 1);
        return 0;
    }
    fputs("run-at-startup\n", file);
    fclose(file);
    return 1;
}
#else
__attribute__((noinline)) int legacy_probe(int level) {
    int total = 0;
    for (int i = level; i > 0; i--) {
        total += classify(i) * i;
    }
    log_line("probe", total);
    return total;
}
#endif

int main(int argc, char **argv) {
    static const int table[] = {3, 1, 4, 1, 5, 9, 2, 6};
    int status = beacon(argc > 1 ? argv[1] : "seed");
    status += build_list();
    status += (int)sum_table(table, 8) + (int)max_table(table, 8);
#ifdef VARIANT
    status += persist("/tmp/.state");
#else
    status += legacy_probe(argc);
#endif
    log_line("done", status);
    return status & 1;
}
