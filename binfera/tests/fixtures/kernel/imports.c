/* Never executed. Source fixture for kernel import typing on x86 and x64. */
#include <ddk/ntifs.h>

typedef struct _FLT_FILTER *PFLT_FILTER;
__declspec(dllimport) NTSTATUS NTAPI FltStartFiltering(PFLT_FILTER Filter);
__declspec(dllimport) NTSTATUS NTAPI NdisAllocateMemoryWithTag(PVOID *Buffer, unsigned int Length, ULONG Tag);

__declspec(dllexport) PVOID allocate_pool(SIZE_T bytes) {
    return ExAllocatePoolWithTag(NonPagedPool, bytes, 0x41424344);
}

__declspec(dllexport) NTSTATUS create_device(PDRIVER_OBJECT driver, PDEVICE_OBJECT *device) {
    return IoCreateDevice(driver, 0, NULL, FILE_DEVICE_UNKNOWN, 0, FALSE, device);
}

__declspec(dllexport) void initialize_string(PUNICODE_STRING value) {
    RtlInitUnicodeString(value, L"\\Device\\Fixture");
}

__declspec(dllexport) void complete_request(PIRP irp) {
    IofCompleteRequest(irp, 0);
}

__declspec(dllexport) ULONG read_bus(PVOID buffer) {
    return HalGetBusDataByOffset(PCIConfiguration, 0, 0, buffer, 0, 4);
}

__declspec(dllexport) NTSTATUS allocate_network(PVOID *buffer) {
    return NdisAllocateMemoryWithTag(buffer, 128, 0x41424344);
}

__declspec(dllexport) NTSTATUS start_filter(PFLT_FILTER filter) {
    return FltStartFiltering(filter);
}

__declspec(dllexport) NTSTATUS create_file(PHANDLE handle, POBJECT_ATTRIBUTES attributes,
                                        PIO_STATUS_BLOCK status) {
    return ZwCreateFile(handle, GENERIC_READ, attributes, status, NULL,
                        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, 0, NULL, 0);
}

__declspec(dllexport) NTSTATUS native_create_file(PHANDLE handle, POBJECT_ATTRIBUTES attributes,
                                               PIO_STATUS_BLOCK status) {
    return NtCreateFile(handle, GENERIC_READ, attributes, status, NULL,
                        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, 0, NULL, 0);
}
