/** What an agent connected through `binfera mcp` can be asked to do with this file. */
export type Effect = "read" | "write" | "report" | "full";

export interface Workflow {
  id: string;
  title: string;
  /** One line for the list. */
  about: string;
  effect: Effect;
  /** The request; `{file}` becomes the file's path and `{topic}` the topic field, if the workflow has one. */
  prompt: string;
  topic?: { label: string; value: string };
}

export interface Group { id: string; title: string; note: string; items: Workflow[] }

export const EFFECTS: Record<Effect, { label: string; hint: string }> = {
  read: { label: "Reads only", hint: "Changes nothing: the agent answers in its chat." },
  write: { label: "Names & comments", hint: "Saves names and comments into this file. Every run can be undone from Activity." },
  report: { label: "Saves a report", hint: "Saves a report with evidence into Reports." },
  full: { label: "Names, comments & report", hint: "Documents the file, then saves a report. Can run for a long time on a large file; every run can be undone from Activity." },
};

// The tools return pseudocode, assembly, strings, imports, callers and capability matches for every
// recovered function, in pages; they do not return raw bytes. The wording below stays inside that.
/** The one request that does everything: document the file, then write it up. Shown first, on its own. */
export const FULL: Workflow = {
  id: "full", title: "Full analysis", effect: "full",
  about: "Documents the application code, then writes a report with evidence. The longest option: on a large file, run Document and Report separately.",
  prompt: "Open {file} with Binfera and do a full analysis in four steps. 1. Orient: read the overview, the capabilities and the most important functions, and decide what this file is and what matters in it. 2. Document: work through the application code bottom-up, skipping library code; name each function, comment the key logic and set confidence honestly; stop when the undocumented list holds only trivial or third-party code. 3. Check: re-read your lowest-confidence names and fix or confirm them. 4. Report: save an analysis report covering what the file is, what it does, its indicators, and its capabilities mapped to MITRE ATT&CK, citing function addresses as evidence and saying plainly what static analysis cannot tell you.",
};

export const GROUPS: Group[] = [
  {
    id: "understand", title: "Understand", note: "Ask questions; nothing is changed.",
    items: [
      { id: "triage", title: "Triage", effect: "read", about: "What is this file, what does it do, how worried should I be?",
        prompt: "Open {file} with Binfera and tell me what it is, what it does and how worried I should be. Read the overview, the capabilities and the most important functions, and back every claim with function addresses." },
      { id: "ask", title: "Ask about a behavior", effect: "read", about: "Find the code behind one behavior and explain it.",
        topic: { label: "about", value: "the network" },
        prompt: "What does {file} do with {topic}? Search its strings and imports, follow them to the code that uses them, and explain what that code does, with function addresses." },
    ],
  },
  {
    id: "document", title: "Document", note: "The agent reads functions and writes names and comments.",
    items: [
      { id: "main", title: "Main functions", effect: "write", about: "The most important functions, with short comments.",
        prompt: "Open {file} with Binfera and document the most important functions: give them meaningful names and short comments." },
      { id: "capabilities", title: "Capability functions", effect: "write", about: "Every function behind a detected capability, and its helpers.",
        prompt: "Open {file} with Binfera and document every function behind a detected capability. For each capability, find the functions that matched, name them after what the capability does there, and comment the lines or instructions that triggered the match. Include the helper functions they call, working bottom-up, and skip library code." },
      { id: "developer", title: "Developer code", effect: "write", about: "What the developer wrote, not library code.",
        prompt: "Open {file} with Binfera and document the code the developer wrote, not library code. Work through the undocumented functions bottom-up, name each by what it does, comment the key logic, and set confidence honestly. Treat statically linked third-party code as library and leave it alone." },
      { id: "everything", title: "Everything", effect: "write", about: "Every application function, until nothing is left. Slow on large files.",
        prompt: "Open {file} with Binfera and document every function that is not library code. Work bottom-up so names build on each other, and keep going until nothing application-level is undocumented. Set confidence honestly." },
      { id: "continue", title: "Continue where it stopped", effect: "write", about: "Pick up from the coverage counters.",
        prompt: "Open {file} with Binfera, check which functions are still undocumented or unexamined, and continue documenting from there without changing existing names." },
      { id: "review", title: "Review the guesses", effect: "write", about: "Re-check low-confidence names and fix the wrong ones.",
        prompt: "Open {file} with Binfera and review the names and comments marked as guesses. Re-read each function, keep the ones you can now support, and replace the wrong ones with better names. Leave anything I wrote myself." },
    ],
  },
  {
    id: "produce", title: "Produce", note: "A write-up you can keep, with evidence.",
    items: [
      { id: "report", title: "Analysis report", effect: "report", about: "Findings backed by evidence from the analysis.",
        prompt: "Analyze {file} with Binfera and write a file analysis report, backed by evidence from the analysis." },
      { id: "iocs", title: "Indicators", effect: "report", about: "URLs, paths, mutexes, keys and commands, each with where it is used.",
        prompt: "Open {file} with Binfera and extract its indicators: URLs, domains, IP addresses, file paths, mutexes, registry keys and command lines. For each, name the function that uses it. Save them as a report." },
      { id: "attack", title: "ATT&CK mapping", effect: "report", about: "Detected capabilities mapped to techniques, with the code behind each.",
        prompt: "Open {file} with Binfera and map its detected capabilities to MITRE ATT&CK techniques. For each technique, cite the capability and the functions that implement it. Save it as a report." },
    ],
  },
  {
    id: "hunt", title: "Hunt", note: "Look for something specific.",
    items: [
      { id: "config", title: "Configuration and C2", effect: "read", about: "How it decodes its configuration, and what that contains.",
        prompt: "Open {file} with Binfera and find how it hides or decodes its configuration and where it contacts. Explain the decoding routine and say what it yields, with function addresses. Say plainly what cannot be known without running it." },
      { id: "crypto", title: "Crypto routines", effect: "write", about: "Find and name encryption, hashing and encoding code.",
        prompt: "Open {file} with Binfera and find its cryptographic and encoding routines. Name each function after the algorithm, comment how keys and data flow into it, and note where the keys come from." },
      { id: "bugs", title: "Vulnerabilities", effect: "read", about: "Unsafe code in what the developer wrote.",
        prompt: "Open {file} with Binfera and look for vulnerabilities in the code the developer wrote: unchecked copies, format strings, missing validation. For each, give the function address, what goes wrong and how likely it is." },
    ],
  },
];

/** The request as the analyst will paste it. A dropped file has no known path, so its name stands in. */
export function request(w: Workflow, file: string, topic?: string) {
  return w.prompt.replace("{file}", file).replace("{topic}", topic?.trim() || w.topic?.value || "");
}
