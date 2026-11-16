"""Install the built desktop package on its CI runner and check its first launch."""
import os
from pathlib import Path
import plistlib
import shutil
import signal
import subprocess
import sys
import tempfile


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, timeout=120)


bundle = Path("src-tauri/target/release/bundle").resolve()
log = Path("src-tauri/target/desktop-smoke.log").resolve()
with tempfile.TemporaryDirectory(prefix="binfera-install-") as scratch:
    installed = Path(scratch) / "installed"
    if sys.platform == "darwin":
        disk = next((bundle / "dmg").glob("*.dmg"))
        mounts = plistlib.loads(run("hdiutil", "attach", "-readonly", "-nobrowse", "-plist", str(disk)).stdout)
        volume = next(Path(e["mount-point"]) for e in mounts["system-entities"] if "mount-point" in e)
        try:
            app = next(volume.glob("*.app"))
            target = installed / app.name
            shutil.copytree(app, target, symlinks=True)
        finally:
            run("hdiutil", "detach", str(volume))
        executable = target / "Contents/MacOS/binfera-desktop"
        command = [str(executable)]
    elif sys.platform == "win32":
        setup = next((bundle / "nsis").glob("*.exe"))
        run(str(setup), "/S", f"/D={installed}")
        executable = next(installed.rglob("binfera-desktop.exe"))
        command = [str(executable)]
    else:
        package = next((bundle / "deb").glob("*.deb"))
        run("sudo", "dpkg", "-i", str(package))
        executable = Path("/usr/bin/binfera-desktop")
        command = ["xvfb-run", "-a", str(executable)]
    assert executable.is_file(), f"Installed app is missing: {executable}"
    env = os.environ.copy()
    if sys.platform.startswith("linux"):
        env["WEBKIT_DISABLE_COMPOSITING_MODE"] = "1"
    with log.open("wb") as output:
        app = subprocess.Popen(command, cwd=executable.parent, env=env,
                               stdout=output, stderr=subprocess.STDOUT,
                               start_new_session=os.name != "nt")
        try:
            code = app.wait(timeout=5)
            raise RuntimeError(f"Desktop app exited during first launch ({code}): {log.read_text(errors='replace')}")
        except subprocess.TimeoutExpired:
            print(f"Installed {executable.name} and kept its first launch alive for five seconds")
        finally:
            if app.poll() is None:
                if os.name == "nt":
                    app.terminate()
                else:
                    os.killpg(app.pid, signal.SIGTERM)
                try:
                    app.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    app.kill()
                    app.wait()
