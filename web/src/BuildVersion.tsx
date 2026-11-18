declare const __BINFERA_BUILD__: { version: string; commit: string | null };

export default function BuildVersion() {
  const { version, commit } = __BINFERA_BUILD__;
  return (
    <span className="build-version">
      v{version} · {commit
        ? <a href={`https://github.com/Karib0u/binfera/commit/${commit}`} title="Source commit" target="_blank" rel="noreferrer"><code>{commit}</code></a>
        : "commit unknown"}
    </span>
  );
}
