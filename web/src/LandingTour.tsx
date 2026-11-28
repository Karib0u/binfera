import { useState } from "react";
import { useTheme } from "./theme";

const REPO = "https://github.com/Karib0u/binfera";

const FEATURES = [
  { title: "Know what it is", image: "overview", alt: "The WannaCry overview: first look, file map and summary counts",
    text: "Offline malware family and library matching, a first look at packing and signatures, a map of the file, and capabilities grouped by ATT&CK tactic." },
  { title: "Read every function", image: "code", alt: "A decompiled function beside its control-flow graph, with the capabilities it matches",
    text: "Typed C with named Windows constants and resolved APIs, plus assembly, listing, control flow, call graph and hex in synced panes, sorted by what matters first." },
  { title: "Work with your AI agent", badge: "Desktop app", image: "ai", alt: "The agent panel open beside a decompiled function in the desktop app",
    text: "Run Claude Code, Codex, Mistral Vibe or any MCP agent beside the code. It reads the analysis through Binfera and saves names, comments and reports. Every run can be undone." },
  { title: "See what changed", image: "compare", alt: "Two builds compared, with a changed function shown as a diff",
    text: "Compare two builds, with the changes worth a look first, down to the instruction." },
  { title: "Follow the data", image: "data", alt: "WannaCry's strings, each linked to the functions that use it",
    text: "Every string links to the functions using it, with library strings filtered out. Open any bytes in hex beside the code, or analyze embedded executables and overlays in one click." },
];

/** What the product does: a feature list driving one large screenshot; on small screens, each feature above its own. */
export default function LandingTour() {
  const [shown, setShown] = useState(0);
  // Each screenshot exists in both themes, so the app in the picture matches the page around it.
  const [theme] = useTheme();
  const suffix = theme === "dark" ? "-dark" : "";
  return (
    <section className="lp-section" id="lp-features" aria-labelledby="lp-tour-title">
      <div className="lp-head">
        <h2 id="lp-tour-title">Built for the <span className="lp-o">first hours</span> with an unknown file</h2>
        <p>What is it, what does it do, and what changed.</p>
      </div>
      <div className="lp-tour">
        {FEATURES.map((f, i) => (
          <div key={f.image} className={"lp-feat" + (i === shown ? " on" : "")}>
            <button type="button" aria-pressed={i === shown} onClick={() => setShown(i)}>
              <h3>{f.title}{f.badge && <em>{f.badge}</em>}</h3>
              <p>{f.text}</p>
            </button>
            <figure><img src={`/landing/${f.image}${suffix}.webp`} width="1600" height="903" loading="lazy" alt={f.alt} /></figure>
          </div>
        ))}
      </div>

      <div className="lp-also">
        <div><h3>Whatever you're handed</h3><p>PE, ELF, Mach-O, .NET or raw shellcode, directly or inside zip and 7z. x86, x64, AArch64, ARM32 and MIPS32, on desktop, browser and mobile.</p></div>
        <div><h3>Code origin and libraries</h3><p>Offline fingerprint packs, FLIRT and Function ID name library code and spot known malware families. Layer your own organization's packs locally.</p></div>
        <div><h3>Your work stays</h3><p>The desktop app keeps renames, comments and recent files, and browses whole folders of samples. <a href={`${REPO}/releases`} target="_blank" rel="noreferrer">Download</a></p></div>
        <div><h3>Function emulation</h3><p>From the command line or MCP, run a function on emulated memory. Sample code never executes on your CPU.</p></div>
        <div><h3>Fast first look</h3><p>A function list a median of 23 times sooner than Ghidra's headless analyzer, on PE, ELF and Mach-O files. <a href={`${REPO}/blob/main/docs/benchmarks.md`} target="_blank" rel="noreferrer">Caveats</a></p></div>
        <div><h3>Scripts and CI</h3><p><code>binfera diff</code> checks builds in a pipeline, and Python bindings expose inspection and decompilation.</p></div>
      </div>
    </section>
  );
}
