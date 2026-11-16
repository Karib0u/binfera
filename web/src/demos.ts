// Real malware samples for the landing page, packed by scripts/pack-demos.mjs. Each file is stored
// XOR-encoded so the site never serves a runnable binary; it is decoded here, in memory, and only
// ever analysed.

export interface DemoSample {
  id: string;
  name: string;
  kind: string;
  tags: string[];
  note: string;
  family: string;
  sha256: string;
  /** Original universal binary hash when the packed demo contains a selected Mach-O slice. */
  sourceSha256?: string;
  size: number;
}

const KEY = new TextEncoder().encode("binfera-demo-sample");
const base = import.meta.env.BASE_URL;

/** The packed samples, or none when the site was built without them. */
export async function listDemos(): Promise<DemoSample[]> {
  try {
    const res = await fetch(`${base}demos/index.json`);
    return res.ok ? await res.json() : [];
  } catch {
    return [];
  }
}

/** Downloads and decodes one sample, named by its SHA-256 as malware repositories name files. */
export async function loadDemo(sample: DemoSample): Promise<File> {
  const res = await fetch(`${base}demos/${sample.id}.bin`);
  if (!res.ok) throw new Error(`sample unavailable (${res.status})`);
  const bytes = new Uint8Array(await res.arrayBuffer());
  for (let i = 0; i < bytes.length; i++) bytes[i] ^= KEY[i % KEY.length];
  return new File([bytes], sample.sha256);
}
