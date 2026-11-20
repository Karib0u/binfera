export interface Annotation { kind: string; target: string; value: string; source: "human" | "ai"; confidence: "certain" | "likely" | "guess"; run_id: string | null; revision: number }
export interface Counts { function_names: number; variable_names: number; comments: number; human: number; ai: number }
export interface Loaded { revision: number; annotations: Annotation[]; counts: Counts }
export interface Edit { kind: "rename_function" | "rename_variable" | "add_comment" | "star"; target: string; value: string; confidence: "certain"; evidence: string[] }
export interface Run { run_id: string; workflow: string; started: number; changes: number }
export interface Change { run_id: string | null; kind: string; target: string; before: string | null; after: string | null; source: "human" | "ai"; confidence: string; revision: number; ts: number; undone: boolean }
export interface Activity { revision: number; runs: Run[]; changes: Change[]; counts: Counts }
export interface ReportInfo { id: number; version: number; title: string; created: number }
export interface McpSetup { command: string; opencode: string; pi: string; vibe: string; database: string }

/** The persistent project database shared with `binfera mcp`; only the desktop build has one. */
export interface ProjectClient {
  load(sha: string, name: string, size: number): Promise<Loaded>;
  /** The available original file or Binfera's saved copy, if either exists. */
  path(sha: string): Promise<string | null>;
  revision(sha: string): Promise<number>;
  apply(sha: string, edits: Edit[]): Promise<number>;
  remove(sha: string, items: { kind: Edit["kind"]; target: string }[]): Promise<number>;
  undo(sha: string, runId: string): Promise<{ reverted: number; skipped: string[]; revision: number }>;
  activity(sha: string): Promise<Activity>;
  reports(sha: string): Promise<ReportInfo[]>;
  report(sha: string, version: number): Promise<{ json: string; markdown: string }>;
  setup(): Promise<McpSetup>;
}

/** A file opened before, as the history lists it. */
export interface Recent {
  sha256: string; name: string;
  /** The original path, if known (archive members have only a filename). */
  path: string | null;
  size: number;
  /** Unix seconds. */
  opened: number;
  human: number; ai: number; reports: number;
  /** Its analysis is stored, so opening it again is immediate. */
  cached: boolean;
  /** Binfera has a saved input that can be reopened without the original file. */
  retained: boolean;
  /** The path no longer holds a file. */
  missing: boolean;
}

/** An executable or archive found in an opened folder. */
export interface FolderFile { path: string; size: number; kind: "pe" | "elf" | "macho" | "zip" | "7z" }
/** A folder and the executables found under it. */
export interface Folder { root: string; name: string; files: FolderFile[]; truncated: boolean }

/** What only the desktop build can do with files: a native picker and a history of opened ones. */
export interface Desktop {
  recent(): Promise<Recent[]>;
  /** Removes a file from the history with its notes, reports and stored analysis; the file stays. */
  forget(sha256: string): Promise<void>;
  /** The system file dialog; with `expect`, only that same binary is accepted. Null when cancelled. */
  pick(expect?: string): Promise<{ file: File; sha256: string } | null>;
  /** Reads a history entry's file again, refusing one that changed since it was analysed. */
  open(entry: Recent): Promise<File>;
  reveal(sha256: string): Promise<void>;
  /** The system folder dialog, then a scan for PE, ELF and Mach-O files. Null when cancelled. */
  pickFolder(): Promise<Folder | null>;
  scanFolder(root: string): Promise<Folder>;
  /** Reads one file of an opened folder (by its path relative to the folder) and records it in the history. */
  openFromFolder(root: string, path: string): Promise<File>;
}
