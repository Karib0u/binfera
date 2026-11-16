extern __SIZE_TYPE__ strlen(const char *);
static const char message[] = "module relocation";
__SIZE_TYPE__ result;
__SIZE_TYPE__ entry(void) { result = strlen(message); return result; }
__SIZE_TYPE__ read_result(void) { return result; }
