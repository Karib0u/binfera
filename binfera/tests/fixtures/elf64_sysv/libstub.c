int puts(const char *s) { (void)s; return 0; }
unsigned long strlen(const char *s) { unsigned long n = 0; while (s[n]) n++; return n; }
void *malloc(unsigned long n) { (void)n; return 0; }
void *memcpy(void *d, const void *s, unsigned long n) { (void)s; (void)n; return d; }
int open(const char *p, int f, ...) { (void)p; (void)f; return -1; }
