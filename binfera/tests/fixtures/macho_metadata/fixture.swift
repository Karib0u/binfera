public struct AuditRecord {
    public var value: Int
    public init(_ value: Int) { self.value = value }
    public func increment() -> Int { value + 7 }
}
@_cdecl("swift_probe")
public func probe(_ value: Int) -> Int { AuditRecord(value).increment() }
