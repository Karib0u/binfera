import Landing from "./Landing";
import { useCompare } from "./views/CompareView";

/** Build-time entry: only the landing page, without the browser-only workspace. */
export default function Prerender() {
  return <Landing onFile={() => {}} compare={useCompare()} />;
}
