#!/usr/bin/env python3
"""Process-level smoke test against dedicated, disposable PostgreSQL/NATS.

Requires built hub/scout binaries, TEST_DATABASE_URL and TEST_NATS_URL.
Creates only fictional observations; it never mounts or reads the real host.
The supplied services must be isolated from other Sentinel instances.
"""

import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import sqlite3
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

from fixture_host import write_host


ROOT = Path(__file__).resolve().parents[1]


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def main() -> None:
    database = os.environ["TEST_DATABASE_URL"]
    nats = os.environ["TEST_NATS_URL"]
    binary_dir = Path(os.environ.get("TEST_BINARY_DIR", ROOT / "target/debug"))
    hub = binary_dir / "hub"
    scout = binary_dir / "scout"
    if not hub.is_file() or not scout.is_file():
        raise RuntimeError("Build hub/scout before running the smoke test")

    with tempfile.TemporaryDirectory(prefix="sentinel-e2e-") as temporary:
        area = Path(temporary)
        host = area / "host"
        state = area / "state"
        write_host(host)
        credential = secrets.token_hex(32)
        credential_file = area / "admin-token"
        credential_file.write_text(credential, encoding="utf-8")
        credential_file.chmod(0o600)
        database_file = area / "database-url"
        database_file.write_text(database + "\n", encoding="utf-8")
        database_file.chmod(0o600)
        bind = f"127.0.0.1:{free_port()}"
        base = f"http://{bind}"
        env = {k: v for k, v in os.environ.items() if not k.startswith("SENTINEL_")}
        env.update({
            "SENTINEL_DATABASE_URL_FILE": str(database_file),
            "SENTINEL_NATS_URL": nats,
            "SENTINEL_ADMIN_TOKEN_FILE": str(credential_file),
            "SENTINEL_BIND": bind,
            "SENTINEL_HUB_URL": base,
            "SENTINEL_HOST_ROOT": str(host),
            "SENTINEL_STATE_DIR": str(state),
            "SENTINEL_ASSET_NAME": "sentinel-e2e-fictional",
            "SENTINEL_WEB_DIR": str(ROOT / "web/dist"),
            "SENTINEL_INTERVAL_SECONDS": "5",
            "RUST_LOG": "warn",
        })

        def request(path: str, method="GET", body=None, *, authenticated=True, expected=200):
            headers = {"Content-Type": "application/json"}
            if authenticated:
                headers["Authorization"] = f"Bearer {credential}"
            data = None if body is None else json.dumps(body).encode()
            req = urllib.request.Request(base + path, data=data, headers=headers, method=method)
            try:
                response = urllib.request.urlopen(req, timeout=5)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                content = response.read()
                assert response.status == expected, (path, response.status, expected, content[:400])
                return json.loads(content) if content else None

        def command(*args: str, enrollment=False, timeout=30, overrides=None):
            process_env = env.copy()
            if not enrollment:
                process_env.pop("SENTINEL_ADMIN_TOKEN_FILE")
            if overrides:
                process_env.update(overrides)
            result = subprocess.run(
                [str(scout), *args], env=process_env, cwd=ROOT,
                capture_output=True, text=True, timeout=timeout,
            )
            assert result.returncode == 0, (args, result.stderr[-2000:], result.stdout[-2000:])
            assert credential not in result.stdout + result.stderr, "credential leaked to logs"
            return result.stdout

        def wait_for(predicate, message: str, timeout=25):
            until = time.monotonic() + timeout
            while time.monotonic() < until:
                if process.poll() is not None:
                    raise RuntimeError("Hub exited during " + message)
                try:
                    value = predicate()
                    if value:
                        return value
                except (urllib.error.URLError, AssertionError):
                    pass
                time.sleep(0.2)
            raise AssertionError("Timed out: " + message)

        log_file = area / "hub.log"
        with log_file.open("w+") as log:
            process = subprocess.Popen([str(hub)], env=env, cwd=ROOT, stdout=log, stderr=log)
            try:
                wait_for(lambda: request("/readyz", authenticated=False), "Hub readiness")
                request("/api/v1/assets", authenticated=False, expected=401)
                session = request("/api/v1/session")
                assert session["mode"] == "development"
                assert request("/api/v1/assets")["items"] == [], "Use an empty disposable test database"
                capabilities = request("/api/v1/capabilities")
                for feature in ("ai", "upgrades", "vulnerability_matching", "baseline", "task_execution"):
                    assert capabilities[feature] is False, feature
                request("/api/v1/tasks", "POST", {}, expected=501)
                request("/api/v1/upgrades", "POST", {}, expected=501)

                command("init")
                assert state.stat().st_mode & 0o077 == 0, "Scout state must be private"
                command("enroll", enrollment=True)
                first = request("/api/v1/assets")["items"]
                assert len(first) == 1
                asset_id = first[0]["id"]
                command("enroll", enrollment=True)
                assert [a["id"] for a in request("/api/v1/assets")["items"]] == [asset_id]
                offline = json.loads(command("once", overrides={
                    "SENTINEL_NATS_URL": f"nats://127.0.0.1:{free_port()}",
                }))
                assert offline["published"] is False
                assert offline["queue"]["pending_events"] == 1
                with sqlite3.connect(state / "state.sqlite3") as local:
                    queued_id, queued_payload = local.execute("SELECT id, payload FROM pending_events").fetchone()
                signed = json.loads(queued_payload)
                payload = json.loads(signed["payload"])
                assert payload["event_id"] == queued_id
                machine_id = (host / "etc/machine-id").read_text().strip()
                expected_fingerprint = hashlib.sha256(b"sentinel:machine-id:v1\0" + machine_id.encode()).hexdigest()
                assert payload["host"]["fingerprint_sha256"] == expected_fingerprint
                assert machine_id.encode() not in queued_payload, "raw machine identity must stay local"
                assert credential.encode() not in queued_payload
                command("once")
                assert json.loads(command("status"))["queue"]["pending_events"] == 0

                def collected():
                    detail = request(f"/api/v1/assets/{asset_id}")
                    return detail if detail["inventory"] and detail["packages"] else None

                detail = wait_for(collected, "Scout → JetStream → PostgreSQL → API")
                assert detail["inventory"]["hostname"] == "sentinel-fixture-01"
                assert detail["inventory"]["os_version"] == "24.04"
                assert {p["name"] for p in detail["packages"]} == {"fixture-openssl", "fixture-lib"}
                package = next(p for p in detail["packages"] if p["name"] == "fixture-openssl")
                assert package["version"] == "3:3.0.13-0ubuntu3.4"
                assert package["source_name"] == "fixture-openssl-source"
                assert len(detail["ports"]) == 4, detail["ports"]
                assert sum(p["loopback"] for p in detail["ports"]) == 2
                assert {p["pid"] for p in detail["processes"]} == {1, 200}
                assert detail["asset"]["metrics"]["process_count"] == 2
                assert detail["asset"]["metrics"]["cpu_percent"] is None

                group = request("/api/v1/groups", "POST", {"name": "Integration fixture"}, expected=201)
                request("/api/v1/groups", "POST", {"name": "Integration fixture"}, expected=409)
                request(f"/api/v1/assets/{asset_id}", "PATCH", {
                    "group_id": group["id"], "tags": {"environment": "fixture"},
                })
                moved = request(f"/api/v1/assets/{asset_id}")["asset"]
                assert moved["group_id"] == group["id"]
                assert moved["tags"] == {"environment": "fixture"}
                assert len(request(f"/api/v1/assets?group_id={group['id']}")["items"]) == 1
                request(f"/api/v1/assets/{asset_id}", "PATCH", {"tags": {"environment": "fixture"}})

                # A new process must reuse the persisted installation and asset.
                write_host(host, version="22.04", sample=1)
                command("once")
                wait_for(lambda: request(f"/api/v1/assets/{asset_id}")["inventory"]["os_version"] == "22.04",
                         "state reuse and newer observation")
                assert len(request("/api/v1/assets")["items"]) == 1
                command("status")
                # Rates require adjacent observations from the same running Scout.
                previous_sequence = request(f"/api/v1/assets/{asset_id}")["asset"]["metrics"]["sequence"]
                daemon_env = env.copy()
                daemon_env.pop("SENTINEL_ADMIN_TOKEN_FILE")
                with (area / "scout.log").open("w+") as scout_log:
                    daemon = subprocess.Popen([str(scout)], env=daemon_env, cwd=ROOT,
                                              stdout=scout_log, stderr=scout_log)
                    try:
                        wait_for(lambda: request(f"/api/v1/assets/{asset_id}")["asset"]["metrics"]["sequence"] > previous_sequence,
                                 "daemon initial observation")
                        live_status = json.loads(command("status"))
                        assert live_status["asset_id"] == asset_id
                        assert len(live_status["public_key"]) == 64
                        assert live_status["queue"]["pending_events"] >= 0
                        write_host(host, version="22.04", sample=2)

                        def rates_available():
                            metrics = request(f"/api/v1/assets/{asset_id}")["asset"]["metrics"]
                            return metrics if metrics["cpu_percent"] is not None else None

                        metrics = wait_for(rates_available, "adjacent CPU/network observations")
                        assert abs(float(metrics["cpu_percent"]) - 10.0) < 0.01, metrics
                        interface = next(n for n in metrics["resource_summary"]["interfaces"] if n["name"] == "eth0")
                        rx, tx = interface["rx_bytes_per_second"], interface["tx_bytes_per_second"]
                        assert rx > 0 and tx > 0 and abs(rx / tx - 2.0) < 0.001, interface
                    finally:
                        daemon.terminate()
                        try:
                            daemon.wait(timeout=15)
                        except subprocess.TimeoutExpired:
                            daemon.kill()
                            daemon.wait()
                    scout_log.flush()
                    scout_log.seek(0)
                    assert credential not in scout_log.read(), "credential leaked to daemon logs"
                assert json.loads(command("status"))["queue"]["pending_events"] == 0
                print("PASS: authorization, enrollment retry, durable offline queue/replay, signed ingestion/fingerprint privacy, host/package/port/process data, groups/tags, restart identity, concurrent status, adjacent CPU/NIC rates, unsupported capabilities")
            except Exception:
                log.flush()
                log.seek(0)
                output = log.read()[-6000:]
                if credential in output:
                    output = output.replace(credential, "[REDACTED]")
                print(output)
                raise
            finally:
                process.terminate()
                try:
                    process.wait(timeout=25)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


if __name__ == "__main__":
    main()
