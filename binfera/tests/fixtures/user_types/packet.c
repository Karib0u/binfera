/* A record reached only through untyped pointers, so a stripped build gives the
   decompiler no structure to show. Never executed by the tests. */
struct packet {
    unsigned int kind;
    unsigned int length;
    unsigned long checksum;
    struct packet *next;
};

__attribute__((noinline)) int packet_score(void *handle) {
    struct packet *packet = handle;
    return (int)(packet->length * 3 + packet->kind) ^ (int)packet->checksum;
}

/* Writes fields through the same pointer it passes on. */
__attribute__((noinline)) int packet_reset(void *handle, unsigned int kind) {
    struct packet *packet = handle;
    packet->kind = kind;
    packet->length = 0;
    packet->checksum = 0;
    return packet_score(handle) + 1;
}

/* Reaches the pointer it passes on through a loop over `next`. */
__attribute__((noinline)) int packet_total(void *head) {
    int total = 0;
    for (struct packet *packet = head; packet; packet = packet->next)
        total += packet_score(packet);
    return total;
}

static struct packet first;

void _start(void) {
    packet_reset(&first, 1);
    packet_total(&first);
    __builtin_trap();
}
