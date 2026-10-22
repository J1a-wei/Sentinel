#!/usr/bin/env python3
"""Run packaged native binaries with fictional data; full units use systemd_smoke.py."""

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path, PurePosixPath
import platform
import subprocess
import tarfile
import tempfile
import threading

from fixture_host import write_host


def unpack(archive: Path, destination: Path) -> None:
    with tarfile.open(archive, "r:gz") as handle:
        seen = set()
        total = 0
        for entry in handle:
            name = PurePosixPath(entry.name)
            assert not name.is_absolute() and ".." not in name.parts
            assert entry.isfile() and entry.name not in seen
            assert (entry.name in {"VERSION", "ARCH", "bin/hub", "bin/scout"}
                    or entry.name.startswith("web/dist/")
                    or entry.name in {"deploy/systemd/sentinel-hub.service", "deploy/systemd/sentinel-scout.service"})
            seen.add(entry.name)
            total += entry.size
            assert total <= 1024 * 1024 * 1024
            target = destination.joinpath(*name.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            source = handle.extractfile(entry)
            assert source is not None
            with source, target.open("xb") as output:
                while chunk := source.read(1024 * 1024):
                    output.write(chunk)
            target.chmod(0o755 if entry.name in {"bin/hub", "bin/scout"} else 0o644)
    assert {"VERSION", "ARCH", "bin/hub", "bin/scout", "web/dist/index.html",
            "deploy/systemd/sentinel-hub.service", "deploy/systemd/sentinel-scout.service"} <= seen
    assert (destination / "ARCH").read_text().strip() == {"x86_64": "amd64", "aarch64": "arm64"}[platform.machine()]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="sentinel-native-smoke-") as temporary:
        area = Path(temporary)
        install = area / "bundle"
        unpack(args.bundle, install)
        host, state = area / "fictional-host", area / "state"
        write_host(host)
        env = {k: v for k, v in os.environ.items() if not k.startswith("SENTINEL_")}
        env.update(SENTINEL_HOST_ROOT=str(host), SENTINEL_STATE_DIR=str(state), RUST_LOG="error")
        scout = str(install / "bin/scout")

        def run(command, overrides=None, expected=0):
            result = subprocess.run([scout, command], env=env | (overrides or {}),
                                    capture_output=True, text=True, timeout=20)
            assert (result.returncode == 0) == (expected == 0), f"unexpected exit for {command}"
            return json.loads(result.stdout)

        doctor = run("doctor")
        assert doctor["collection_allowed"] and doctor["host_root"] == str(host)
        assert not state.exists(), "doctor must not create identity or state"
        for mode in ("native", "container"):
            assert run("doctor", {"SENTINEL_RUNTIME_MODE": mode})["collection_allowed"]
        assert not run("doctor", {"SENTINEL_HOST_ROOT": str(area / "absent")}, expected=1)["collection_allowed"]
        initialized = run("init")
        assert run("init")["installation_id"] == initialized["installation_id"]
        assert run("status")["installation_id"] == initialized["installation_id"]

        class Ready(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200 if self.path == "/readyz" else 404)
                self.end_headers()

            def log_message(self, *_args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Ready)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            health = subprocess.run([str(install / "bin/hub"), "health"],
                                    env=env | {"SENTINEL_BIND": f"127.0.0.1:{server.server_port}"},
                                    capture_output=True, timeout=10)
            assert health.returncode == 0, "packaged Hub health command failed"
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=5)

        print("PASS: native bundle layout, runtime diagnostics, identity persistence and Hub executable")


if __name__ == "__main__":
    main()
