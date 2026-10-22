#!/usr/bin/env python3
"""Build a native release bundle without requiring a container runtime.

The published bundles are built on Ubuntu 22.04 for its glibc baseline. A local
bundle is a development artifact until the release workflow signs its bytes.
"""

import argparse
import io
import os
from pathlib import Path
import platform
import re
import struct
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
ARCHES = {"x86_64": ("amd64", 62), "aarch64": ("arm64", 183)}


def regular_file(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"expected a regular file: {path}")


def verify_binary(path: Path, machine: int) -> None:
    regular_file(path)
    with path.open("rb") as handle:
        header = handle.read(64)
    if (len(header) != 64 or header[:6] != b"\x7fELF\x02\x01"
            or struct.unpack_from("<H", header, 18)[0] != machine):
        raise ValueError(f"binary is not a native 64-bit ELF for this architecture: {path}")
    result = subprocess.run(
        ["readelf", "--version-info", str(path)], check=True,
        capture_output=True, text=True, env=os.environ | {"LC_ALL": "C"},
    )
    versions = [tuple(map(int, v.split(".")))
                for v in re.findall(r"\bGLIBC_(\d+\.\d+(?:\.\d+)?)", result.stdout)]
    if versions and max(versions) > (2, 35):
        raise ValueError("binary requires glibc newer than 2.35; build on Ubuntu 22.04")


def bundle(args: argparse.Namespace) -> Path:
    if platform.system() != "Linux" or platform.machine() not in ARCHES:
        raise ValueError("native bundles support Linux amd64/arm64")
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:[-.][0-9A-Za-z.]+)?", args.version):
        raise ValueError("--version must be vX.Y.Z, optionally with a release suffix")
    arch, machine = ARCHES[platform.machine()]
    target = args.output_dir.resolve() / f"sentinel-{args.version}-linux-{arch}.tar.gz"
    if target.exists():
        raise ValueError("output bundle already exists; choose a fresh output directory")
    if not args.skip_build:
        subprocess.run(["cargo", "build", "--release", "--locked", "--bin", "hub", "--bin", "scout"], cwd=ROOT, check=True)
        subprocess.run(["npm", "--prefix", "web", "ci"], cwd=ROOT, check=True)
        subprocess.run(["npm", "--prefix", "web", "run", "build"], cwd=ROOT, check=True)
    files = []
    for name in ("hub", "scout"):
        binary = args.binary_dir.resolve() / name
        verify_binary(binary, machine)
        files.append((binary, f"bin/{name}", 0o755))
        unit = ROOT / "deploy/systemd" / f"sentinel-{name}.service"
        regular_file(unit)
        files.append((unit, f"deploy/systemd/sentinel-{name}.service", 0o644))
    web = args.web_dir.resolve()
    regular_file(web / "index.html")
    for path in sorted(web.rglob("*")):
        if path.is_symlink():
            raise ValueError("web assets must not contain symbolic links")
        if path.is_dir():
            continue
        regular_file(path)
        files.append((path, "web/dist/" + path.relative_to(web).as_posix(), 0o644))
    target.parent.mkdir(parents=True, exist_ok=True)
    # Stage privately; only publish a complete archive, without replacing one.
    with tempfile.TemporaryDirectory(prefix="sentinel-bundle-", dir=target.parent) as temporary:
        archive = Path(temporary) / "bundle.tar.gz"
        with tarfile.open(archive, "w:gz", format=tarfile.USTAR_FORMAT) as output:
            for name, value in (("VERSION", args.version), ("ARCH", arch)):
                data = (value + "\n").encode()
                info = tarfile.TarInfo(name)
                info.size, info.mode = len(data), 0o644
                output.addfile(info, io.BytesIO(data))
            for path, name, mode in files:
                info = tarfile.TarInfo(name)
                info.size, info.mode = path.stat().st_size, mode
                with path.open("rb") as handle:
                    output.addfile(info, handle)
        os.chmod(archive, 0o644)
        os.link(archive, target)
    return target


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "dist")
    parser.add_argument("--skip-build", action="store_true", help="package existing, explicitly selected local binaries and assets")
    parser.add_argument("--binary-dir", type=Path, default=ROOT / "target/release")
    parser.add_argument("--web-dir", type=Path, default=ROOT / "web/dist")
    args = parser.parse_args()
    try:
        output = bundle(args)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"native bundle failed: {error}\n")
    print(f"Created unsigned local bundle: {output}")


if __name__ == "__main__":
    main()
