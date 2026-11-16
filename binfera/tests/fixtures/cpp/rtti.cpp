// C++ with MSVC RTTI and no C runtime: classes with virtual methods, single and multiple
// inheritance, a decorated import and decorated exports. Built by build.sh for x86 and x64.
typedef __SIZE_TYPE__ size_t;

#ifdef _WIN32
#define IMPORT __declspec(dllimport)
#define EXPORT __declspec(dllexport)
#define NOINLINE __declspec(noinline)
#else
#define IMPORT
#define EXPORT __attribute__((visibility("default")))
#define NOINLINE __attribute__((noinline))
#define __stdcall
#define __cdecl
#endif

extern "C" IMPORT unsigned long __stdcall GetTickCount(void);

// The C runtime normally supplies these; the fixture links none.
extern "C" const void *fixture_type_info_vftable[2] = {0, 0};
extern "C" int __cdecl _purecall(void) { return 0; }
void operator delete(void *, size_t) {}
void operator delete(void *) {}
inline void *operator new(size_t, void *place) { return place; }

namespace std {
// An import from the C++ runtime DLL, decorated (msvcp.def).
class _Lockit {
public:
    IMPORT explicit _Lockit(int kind);
    IMPORT ~_Lockit();
private:
    int locktype;
};
}

namespace net {
class Channel {
public:
    virtual ~Channel() {}
    virtual int send(const char *data, int size) = 0;
    virtual int recv(char *buffer, int size) { return size - sent; }
    int sent = 0;
};

class TcpChannel : public Channel {
public:
    NOINLINE TcpChannel(int fd) : socket(fd) {}
    int send(const char *data, int size) override {
        sent += size;
        return size + socket + (int)GetTickCount();
    }
    int recv(char *buffer, int size) override {
        buffer[0] = (char)socket;
        return this->Channel::recv(buffer, size) + 1;
    }
    int socket;
};

class Logger {
public:
    virtual void log(int value) = 0;
    virtual int level() { return 3; }
};

class LoggingChannel : public TcpChannel, public Logger {
public:
    NOINLINE LoggingChannel(int fd) : TcpChannel(fd) {}
    void log(int value) override { total += value * level(); }
    int send(const char *data, int size) override {
        log(size);
        // A virtual call through this object's own table.
        return TcpChannel::send(data, size) + recv((char *)data, size);
    }
    int total = 0;
};

template <typename T> class Box {
public:
    virtual T get() { return value; }
    virtual void set(T next) { value = next; }
    T value;
};
}

// Exported with decorated names.
class EXPORT Counter {
public:
    int add(int value);
    static Counter *instance();
    int count;
};
int Counter::add(int value) { count += value; return count; }
Counter *Counter::instance() { static Counter one; return &one; }

extern "C" EXPORT NOINLINE int use_channel(net::Channel *channel, char *buffer) {
    std::_Lockit lock(2);
    return channel->send(buffer, 4) + channel->recv(buffer, 8);
}

extern "C" EXPORT NOINLINE net::Channel *make_channel(void *memory, int kind) {
    if (kind == 0) return new (memory) net::TcpChannel(7);
    return new (memory) net::LoggingChannel(9);
}

extern "C" EXPORT NOINLINE int use_box(void *memory) {
    net::Box<int> *box = new (memory) net::Box<int>();
    box->set(5);
    return box->get();
}

// A COM-style interface: its methods are `__stdcall`, with `this` on the stack on x86.
struct IThing {
    virtual long __stdcall QueryValue(int id) = 0;
    virtual unsigned long __stdcall AddRef() = 0;
};
class Thing : public IThing {
public:
    long __stdcall QueryValue(int id) override { return id + count; }
    unsigned long __stdcall AddRef() override { return ++count; }
    int count = 0;
};

extern "C" EXPORT NOINLINE long use_thing(void *memory) {
    IThing *thing = new (memory) Thing();
    thing->AddRef();
    return thing->QueryValue(3);
}

extern "C" int __stdcall _DllMainCRTStartup(void *, unsigned long, void *) { return 1; }
