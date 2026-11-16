import type { Arch } from "../types";

/** Normalized file metadata from Rust's image_info API. */
export interface Section { name: string; va: number; vsize: number; off: number; size: number; perms: string; entropy: number }
export interface ImportEntry { dll: string; name: string; /** Address of the import's pointer slot. */ va: number }
export interface ExportEntry { name: string; va: number; forward?: string }
export interface Region { off: number; size: number; va: number }

/** One header field; `value` is preformatted, since 64-bit values do not survive JSON numbers. */
export interface StructField { name: string; off: number; size: number; value: string; note?: string; target?: number }
export interface Structure { name: string; off: number; size: number; va?: number; fields: StructField[] }
export interface Fact { group: string; label: string; value: string; va?: number }
export interface Anomaly { severity: "warn" | "info"; text: string; va?: number }
export interface Overlay { off: number; size: number; entropy: number; kind?: string }
export interface Resource { type: string; name: string; lang: string; va: number; off?: number; size: number; entropy?: number; detected?: string }
export interface Property { label: string; value: string }
export interface Certificate { subject: string; issuer: string; serial: string; notBefore: string; notAfter: string; sha1: string; sha256: string; signer: boolean; selfSigned: boolean }
export interface Signature {
  kind: string; off: number; size: number;
  digestAlgorithm?: string; signedDigest?: string; computedDigest?: string; digestMatches?: boolean;
  program?: string; signingTime?: string; timestamp?: string; timestampSigner?: string;
  properties: Property[]; certificates: Certificate[]; entitlements?: string;
}
export interface FileDetails {
  structures: Structure[]; facts: Fact[]; anomalies: Anomaly[]; overlay?: Overlay;
  resources: Resource[]; versionInfo: Property[]; manifest?: string; signatures: Signature[];
}

export interface ImageMetadata {
  shellcode?: { ambiguous: boolean; x86Score: number; x64Score: number; os: "windows" | "linux" | null; evidence: string[] };
  format: string;
  arch: Arch;
  fidArch: "x86" | "x64" | null;
  entry: number | null;
  ptrSize: number;
  littleEndian: boolean;
  warnings: string[];
  sections: Section[];
  regions: Region[];
  imports: ImportEntry[];
  exports: ExportEntry[];
  /** Absent only in metadata from an engine older than this page. */
  details?: FileDetails;
}

/** Raw input bytes and presentation helpers over the engine's address mappings. */
export interface ImageInfo extends ImageMetadata {
  bytes: Uint8Array;
  vaToOff(va: number): number | null;
  offToVa(off: number): number | null;
  sectionAt(va: number): Section | undefined;
}

export function createImage(bytes: Uint8Array, metadata: ImageMetadata): ImageInfo {
  const { sections, regions } = metadata;
  return {
    ...metadata, bytes,
    vaToOff(va) {
      for (const r of regions) if (va >= r.va && va < r.va + r.size) return r.off + va - r.va;
      return null;
    },
    offToVa(off) {
      for (const r of regions) if (off >= r.off && off < r.off + r.size) return r.va + off - r.off;
      return null;
    },
    sectionAt(va) {
      return sections.find(s => va >= s.va && va < s.va + Math.max(s.vsize, s.size));
    },
  };
}
