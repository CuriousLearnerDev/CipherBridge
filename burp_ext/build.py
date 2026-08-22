"""Build CipherBridge Burp Upstream extension JAR (no Maven required)."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
STUBS = ROOT / "stubs"
SRC = ROOT / "src"
OUT = ROOT / "out"
DIST_DIR = ROOT.parent / "tools" / "burp"
JAR_NAME = "CipherBridge-Upstream.jar"


def find_javac() -> Path:
    env = os.environ.get("JAVA_HOME")
    if env:
        p = Path(env) / "bin" / "javac.exe"
        if p.is_file():
            return p
    candidates = [
        Path(r"C:\Program Files\Java\jdk-1.8\bin\javac.exe"),
        Path(r"C:\Program Files\Java\latest\bin\javac.exe"),
    ]
    for c in candidates:
        if c.is_file():
            return c
    # last resort
    which = shutil.which("javac")
    if which:
        return Path(which)
    raise SystemExit("javac not found — install JDK 8+")


def main() -> None:
    javac = find_javac()
    jar_bin = javac.parent / ("jar.exe" if os.name == "nt" else "jar")
    if not jar_bin.is_file():
        raise SystemExit(f"jar tool not found next to javac: {jar_bin}")

    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)
    DIST_DIR.mkdir(parents=True, exist_ok=True)

    sources = list(STUBS.rglob("*.java")) + list(SRC.rglob("*.java"))
    if not sources:
        raise SystemExit("no Java sources")

    cmd = [
        str(javac),
        "-encoding",
        "UTF-8",
        "-source",
        "1.8",
        "-target",
        "1.8",
        "-d",
        str(OUT),
    ] + [str(p) for p in sources]
    print("compile:", " ".join(cmd[:8]), f"... ({len(sources)} files)")
    subprocess.check_call(cmd)

    # Do not package stub interfaces — Burp provides burp.* at runtime
    for stub_class in OUT.joinpath("burp").glob("I*.class"):
        stub_class.unlink()

    jar_path = DIST_DIR / JAR_NAME
    if jar_path.exists():
        jar_path.unlink()
    # Only our BurpExtender.class should remain under burp/
    cmd_jar = [str(jar_bin), "cf", str(jar_path), "-C", str(OUT), "."]
    print("jar:", " ".join(cmd_jar))
    subprocess.check_call(cmd_jar)
    print("OK:", jar_path)
    print("size:", jar_path.stat().st_size, "bytes")


if __name__ == "__main__":
    main()
