#include <objc/runtime.h>
__attribute__((objc_root_class))
@interface AuditObject
+ (id)new;
- (long)add:(long)value;
@end
@implementation AuditObject
+ (id)new { return class_createInstance(self, 0); }
- (long)add:(long)value { return value + 42; }
@end
@interface AuditObject (Extra)
- (long)extra;
@end
@implementation AuditObject (Extra)
- (long)extra { return 17; }
@end
long probe(AuditObject *object) { return [object add:7] + [object extra]; }
int main(void) { return (int)probe([AuditObject new]); }
