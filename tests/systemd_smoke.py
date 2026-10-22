#!/usr/bin/env python3
"""CI-only acceptance of the native bundle's actual Hub and Scout service units.

Run on a fresh GitHub Ubuntu runner, with disposable PostgreSQL 17 and JetStream:
  sudo --preserve-env=TEST_DATABASE_URL,TEST_NATS_URL,GITHUB_ACTIONS \
    python3 tests/systemd_smoke.py --bundle dist/sentinel-vX.Y.Z-linux-amd64.tar.gz

This script never invokes sudo, installs dependencies, or stops dependency services.
It uses fictional host files only. Credentials and database URLs are never printed.
Local syntax/unit inspection is useful, but is not a substitute for running this
system-service acceptance test in CI.
"""

import argparse
import grp
import hashlib
from html.parser import HTMLParser
import json
import os
from pathlib import Path, PurePosixPath
import platform
import pwd
import re
import secrets
import shutil
import signal
import socket
import sqlite3
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

from fixture_host import write_host


class Failure(Exception):
    """A safe, static diagnostic; never include command output or credentials."""


def require(condition, message):
    if not condition:
        raise Failure(message)


def clean_env():
    return {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C.UTF-8",
        "SYSTEMD_COLORS": "0",
        "SYSTEMD_PAGER": "cat",
    }


def command(argv, label, *, env=None, timeout=45, check=True):
    try:
        result = subprocess.run(argv, env=clean_env() if env is None else env,
                                capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        raise Failure(label + " could not finish") from None
    if check:
        require(result.returncode == 0, label + " failed")
    return result


def wait_for(predicate, label, timeout=75):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            value = predicate()
            if value:
                return value
        except (urllib.error.URLError, ConnectionError, TimeoutError):
            pass
        time.sleep(0.25)
    raise Failure("timed out: " + label)


def checked_endpoints(database, nats):
    try:
        db = urllib.parse.urlsplit(database)
        broker = urllib.parse.urlsplit(nats)
        require(db.scheme in {"postgres", "postgresql"}
                and db.hostname in {"127.0.0.1", "localhost", "::1"}
                and db.path == "/sentinel_native" and db.username == "sentinel"
                and db.port in {None, 5432} and not db.query and not db.fragment,
                "database must be the isolated loopback sentinel_native fixture")
        require(broker.scheme == "nats"
                and broker.hostname in {"127.0.0.1", "localhost", "::1"}
                and broker.port == 14228 and not broker.username and not broker.password
                and broker.path in {"", "/"} and not broker.query and not broker.fragment,
                "NATS must be the isolated loopback fixture on port 14228")
        require(not any(c in database + nats for c in "\r\n\x00"),
                "invalid test endpoint characters")
    except ValueError:
        raise Failure("invalid test endpoint") from None


def unpack(archive, destination):
    """Do not repair bad modes or accept links while checking a release layout."""
    required = {"VERSION", "ARCH", "bin/hub", "bin/scout", "web/dist/index.html",
                "deploy/systemd/sentinel-hub.service", "deploy/systemd/sentinel-scout.service"}
    seen, total = set(), 0
    with tarfile.open(archive, "r:gz") as handle:
        for entry in handle:
            path = PurePosixPath(entry.name)
            require(not path.is_absolute() and ".." not in path.parts
                    and str(path) == entry.name and entry.name not in seen
                    and entry.isfile(), "bundle contains an unsafe or duplicate entry")
            require(entry.name in required or entry.name.startswith("web/dist/"),
                    "bundle contains an unexpected entry")
            total += entry.size
            seen.add(entry.name)
            require(0 <= entry.size <= 512 * 1024 * 1024
                    and total <= 1024 * 1024 * 1024 and len(seen) <= 4096,
                    "bundle exceeds test extraction limits")
            mode = 0o755 if entry.name in {"bin/hub", "bin/scout"} else 0o644
            require(entry.mode == mode, "bundle has incorrect installed file permissions")
            target = destination.joinpath(*path.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            source = handle.extractfile(entry)
            require(source is not None, "bundle entry has no contents")
            with source, target.open("xb") as output:
                shutil.copyfileobj(source, output, length=1024 * 1024)
            target.chmod(mode)
    require(required <= seen, "bundle is missing a required component")
    arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
    require(arch and (destination / "ARCH").read_text().strip() == arch,
            "bundle architecture does not match the runner")
    require(re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:[-.][0-9A-Za-z.]+)?",
                         (destination / "VERSION").read_text().strip()),
            "bundle has invalid version metadata")
    # The unprivileged Hub must be able to traverse the non-secret bundle.
    destination.chmod(0o755)
    for path in destination.rglob("*"):
        if path.is_dir():
            path.chmod(0o755)


def directives(text):
    """Retain duplicate directives; never silently collapse ExecStart/Environment."""
    section, result = None, {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        require(not line.endswith("\\") and "\x00" not in line,
                "unit inspection needs an update for this directive syntax")
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
        else:
            require(section and "=" in line, "malformed packaged service unit")
            key, value = line.split("=", 1)
            result.setdefault((section, key.strip()), []).append(value.strip())
    return result


def one(values, section, key):
    found = values.get((section, key), [])
    require(len(found) == 1 and found[0], "unit must have exactly one " + key)
    return found[0]


def write_private(path, value, *, owner=None):
    with path.open("x", encoding="utf-8") as output:
        output.write(value)
    path.chmod(0o600)
    if owner:
        os.chown(path, *owner)


def environment_text(values):
    for key, value in values.items():
        require(re.fullmatch(r"[A-Z][A-Z0-9_]*", key)
                and not any(c in value for c in "\n\r\x00\"\\"),
                "unsupported test environment value")
    return "".join(f'{key}="{value}"\n' for key, value in values.items())


def public_identity(status):
    return tuple(status[name] for name in ("installation_id", "asset_id", "public_key"))


def queue_snapshot(state):
    """Read only fictional queued data, never the local signing seed."""
    with sqlite3.connect((state / "state.sqlite3").as_uri() + "?mode=ro",
                         uri=True, timeout=5) as connection:
        connection.execute("PRAGMA query_only=ON")
        connection.execute("BEGIN")
        epoch, sequence = connection.execute(
            'SELECT active_epoch, metric_sequence FROM local_identity WHERE NOT "delete"'
        ).fetchone()
        rows = connection.execute(
            'SELECT id, sequence, payload FROM pending_events WHERE NOT "delete"'
        ).fetchall()
    return epoch, sequence, {
        event: (number, hashlib.sha256(payload).hexdigest()) for event, number, payload in rows
    }


class Assets(HTMLParser):
    def __init__(self):
        super().__init__()
        self.paths = set()

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        value = attrs.get("src") if tag == "script" else (
            attrs.get("href") if tag == "link" else None)
        if value:
            self.paths.add(value)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


class Http:
    def __init__(self, base, credential):
        self.base, self.credential = base, credential
        self.client = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def get(self, path, *, authenticated=True, expected=200, json_body=True):
        headers = {"Authorization": "Bearer " + self.credential} if authenticated else {}
        request = urllib.request.Request(self.base + path, headers=headers)
        try:
            response = self.client.open(request, timeout=4)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            body = response.read(8 * 1024 * 1024 + 1)
            require(len(body) <= 8 * 1024 * 1024, "HTTP response is unexpectedly large")
            require(response.status == expected, "HTTP response status did not match")
            return json.loads(body) if json_body else body

    def ready(self):
        try:
            return bool(self.get("/readyz", authenticated=False))
        except Failure:
            return False

    def frontend(self, bundle):
        content = self.get("/", authenticated=False, json_body=False)
        require(content == (bundle / "web/dist/index.html").read_bytes(),
                "Hub is not serving the bundled index")
        parser = Assets()
        parser.feed(content.decode("utf-8"))
        require(any(p.endswith(".js") for p in parser.paths), "frontend has no built JavaScript")
        for value in parser.paths:
            url = urllib.parse.urlsplit(value)
            require(not url.scheme and not url.netloc and not url.query and not url.fragment
                    and url.path.startswith("/assets/") and ".." not in PurePosixPath(url.path).parts,
                    "frontend references an unexpected asset path")
            expected = bundle / "web/dist" / url.path.lstrip("/")
            require(expected.is_file() and self.get(url.path, authenticated=False, json_body=False)
                    == expected.read_bytes(), "Hub static asset is missing or differs from the bundle")


def fixture_observation(http, asset_id):
    detail = http.get("/api/v1/assets/" + asset_id)
    if not detail.get("inventory") or not detail.get("packages") or not detail["asset"].get("metrics"):
        return None
    require(detail["inventory"]["hostname"] == "sentinel-fixture-01",
            "observation is not from the fictional host")
    require({p["name"] for p in detail["packages"]} == {"fixture-openssl", "fixture-lib"}
            and {p["pid"] for p in detail["processes"]} == {1, 200}
            and len(detail["ports"]) == 4, "fixture inventory did not reach the real API")
    return detail


def render_unit(source, component, install, env_file, state, hub_user):
    """Transform only documented installation paths, user/group and state basename.

    The full packaged unit remains the service under test. In particular, this
    must not replace ExecStart, ExecStartPre, restart policy or sandbox settings
    with a hand-written/transient unit or a permissive drop-in.
    """
    values = directives(source)
    expected = {
        "Type": "exec", "User": "sentinel-hub" if component == "hub" else "root",
        "Group": "sentinel-hub" if component == "hub" else "root",
        "WorkingDirectory": "/opt/sentinel/hub" if component == "hub" else "/var/lib/sentinel-scout",
        "EnvironmentFile": f"/etc/sentinel/{component}/{component}.env",
        "ExecStart": f"/opt/sentinel/{component}/bin/{component}",
        "Restart": "on-failure", "StateDirectory": f"sentinel-{component}",
        "StateDirectoryMode": "0700", "UMask": "0077", "NoNewPrivileges": "yes",
        "ProtectSystem": "strict", "PrivateTmp": "yes",
    }
    for key, value in expected.items():
        require(one(values, "Service", key) == value,
                "packaged " + component + " unit differs from the installation contract: " + key)
    if component == "scout":
        require(one(values, "Service", "ExecStartPre") == "/opt/sentinel/scout/bin/scout doctor",
                "packaged Scout must perform its real doctor preflight")
        require(values.get(("Service", "Environment")) == [
            "SENTINEL_RUNTIME_MODE=auto", "SENTINEL_STATE_DIR=/var/lib/sentinel-scout"],
            "Scout unit must retain auto mode and persistent state environment")
    else:
        require(values.get(("Service", "Environment")) == [
            "SENTINEL_WEB_DIR=/opt/sentinel/hub/web/dist"],
            "Hub unit must point to the installed frontend")
    rendered = source.replace(f"/opt/sentinel/{component}", str(install))
    rendered = rendered.replace(f"/etc/sentinel/{component}/{component}.env", str(env_file))
    rendered = rendered.replace(f"/var/lib/sentinel-{component}", str(state))
    replacements = {"StateDirectory": state.name}
    if component == "hub":
        replacements.update(User=hub_user, Group=hub_user)
    section, lines = None, []
    for line in rendered.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1]
        key = stripped.partition("=")[0]
        if section == "Service" and key in replacements:
            line = key + "=" + replacements[key]
        lines.append(line)
    rendered = "\n".join(lines) + "\n"
    after = directives(rendered)
    allowed = {("Service", key) for key in (
        "User", "Group", "WorkingDirectory", "Environment", "EnvironmentFile",
        "ExecStart", "ExecStartPre", "StateDirectory",
    )}
    require(values.keys() == after.keys(), "unit transformation changed directive keys")
    for key, value in values.items():
        require(key in allowed or after[key] == value,
                "unit transformation changed a non-path directive")
    require(one(after, "Service", "StateDirectory") == state.name
            and one(after, "Service", "ExecStart") == str(install / "bin" / component),
            "incorrect unit path transformation")
    return rendered


def no_existing_installation():
    roots = ("/opt/sentinel", "/etc/sentinel", "/var/lib/sentinel", "/var/log/sentinel",
             "/run/sentinel", "/var/lib/sentinel-hub", "/var/lib/sentinel-scout",
             "/usr/local/lib/sentinel", "/usr/local/bin/sentinel-hub", "/usr/local/bin/sentinel-scout")
    require(not any(os.path.lexists(p) for p in roots),
            "refusing a runner with existing Sentinel installation directories")
    for name in ("sentinel", "sentinel-hub", "sentinel-scout"):
        for lookup in (pwd.getpwnam, grp.getgrnam):
            try:
                lookup(name)
            except KeyError:
                continue
            raise Failure("refusing a runner with existing Sentinel users or groups")
    for name in ("sentinel-hub.service", "sentinel-scout.service"):
        for root in ("/etc/systemd/system", "/run/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"):
            require(not os.path.lexists(Path(root) / name)
                    and not os.path.lexists(Path(root) / (name + ".d"))
                    and not any(Path(root).glob("*.wants/" + name))
                    and not any(Path(root).glob("*.requires/" + name)),
                    "refusing a runner with an existing formal service unit")
        result = command(["systemctl", "show", "--property=LoadState", "--value", name],
                         "inspect formal service absence", check=False)
        require(result.stdout.strip() == "not-found", "refusing an existing formal service")


class Services:
    """Resource ledger: cleanup operates only on resources this invocation created."""
    def __init__(self):
        self.tag = "sentinel-smoke-" + secrets.token_hex(6)
        self.username = "ssm-" + self.tag.rsplit("-", 1)[1]
        self.area = None
        self.user = None
        self.group = None
        self.directories = []
        self.units = {}
        self.names = {c: self.tag + "-" + c + ".service" for c in ("hub", "scout")}
        self.states = {c: Path("/var/lib") / (self.tag + "-" + c) for c in self.names}

    def properties(self, component):
        result = command(["systemctl", "show", self.names[component],
                          "--property=LoadState,ActiveState,SubState,MainPID,NRestarts,Result,ExecMainStatus"],
                         "inspect test service")
        return dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)

    def action(self, action, component):
        command(["systemctl", action, self.names[component]], action + " test " + component,
                timeout=60)

    def active(self, component):
        values = self.properties(component)
        return values if values.get("ActiveState") == "active" and int(values.get("MainPID", "0")) > 0 else None

    def prepare(self, archive):
        for lookup in (pwd.getpwnam, grp.getgrnam):
            try:
                lookup(self.username)
            except KeyError:
                continue
            raise Failure("random test user/group already exists")
        for state in self.states.values():
            require(not os.path.lexists(state), "random test state directory already exists")
        for name in self.names.values():
            for root in ("/run/systemd/system", "/etc/systemd/system"):
                require(not os.path.lexists(Path(root) / name)
                        and not os.path.lexists(Path(root) / (name + ".d")),
                        "random test service name already exists")
            result = command(["systemctl", "show", "--property=LoadState", "--value", name],
                             "inspect test service absence", check=False)
            require(result.stdout.strip() == "not-found", "random test service is already loaded")
        # /opt is visible with both PrivateTmp and ProtectHome; unlike /run it
        # does not depend on a distribution's tmpfs noexec mount policy.
        self.area = Path(tempfile.mkdtemp(prefix=self.tag + "-", dir="/opt"))
        self.area.chmod(0o755)
        self.bundle = self.area / "bundle"
        unpack(archive, self.bundle)
        self.install = self.area / "install"
        self.config = self.area / "config"
        self.install.mkdir(mode=0o755)
        self.config.mkdir(mode=0o755)
        self.install.chmod(0o755)
        self.config.chmod(0o755)
        for component in self.names:
            directory = self.install / component
            (directory / "bin").mkdir(parents=True, mode=0o755)
            directory.chmod(0o755)
            (directory / "bin").chmod(0o755)
            shutil.copy2(self.bundle / "bin" / component, directory / "bin" / component)
        shutil.copytree(self.bundle / "web", self.install / "hub/web")
        # Record even a partially successful useradd, so finally can clean up
        # exactly this new user/group after a later validation or command error.
        try:
            result = command(["useradd", "--system", "--user-group", "--no-create-home",
                              "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", self.username],
                             "create dedicated test Hub user", check=False)
        finally:
            try:
                account = pwd.getpwnam(self.username)
                self.user = (account.pw_uid, account.pw_gid)
            except KeyError:
                pass
            try:
                self.group = grp.getgrnam(self.username).gr_gid
            except KeyError:
                pass
        require(result.returncode == 0 and self.user and self.group == self.user[1],
                "could not create the dedicated test account")
        for component, path in self.states.items():
            path.mkdir(mode=0o700)
            self.directories.append(path)
            if component == "hub":
                os.chown(path, *self.user)
        self.env_files = {c: self.config / (c + ".env") for c in self.names}
        self.host = self.area / "fictional-host"
        write_host(self.host)
        for component, name in self.names.items():
            source = (self.bundle / "deploy/systemd" / ("sentinel-" + component + ".service")).read_text()
            rendered = render_unit(source, component, self.install / component,
                                   self.env_files[component], self.states[component], self.username)
            path = Path("/run/systemd/system") / name
            # x mode is intentional: never replace a service, including a dangling symlink.
            with path.open("x", encoding="utf-8") as output:
                metadata = os.fstat(output.fileno())
                self.units[path] = (metadata.st_dev, metadata.st_ino)
                output.write(rendered)
            path.chmod(0o644)

    def cleanup(self):
        errors, stopped = [], True
        for path in reversed(self.units):
            try:
                metadata = path.lstat()
                require(path.is_file() and not path.is_symlink()
                        and (metadata.st_dev, metadata.st_ino) == self.units[path],
                        "owned service unit changed unexpectedly")
                result = command(["systemctl", "show", "--property=LoadState", "--value", path.name],
                                 "inspect owned unit during cleanup", check=False)
                if result.stdout.strip() != "not-found":
                    command(["systemctl", "stop", path.name], "stop owned test service", timeout=60)
                    result = command(["systemctl", "show", "--property=MainPID", "--value", path.name],
                                     "verify test process stopped")
                    require(result.stdout.strip() == "0", "owned test service is still running")
            except (Failure, OSError):
                errors.append("could not stop an owned test service")
                stopped = False
        if not stopped:
            # Never remove state or accounts out from under a live process.
            return errors
        for path in self.units:
            try:
                command(["systemctl", "reset-failed", path.name], "reset owned service", check=False)
                path.unlink()
            except (Failure, OSError):
                errors.append("could not remove an owned test unit")
        if self.units:
            try:
                command(["systemctl", "daemon-reload"], "reload after test unit removal")
            except Failure:
                errors.append("could not reload systemd after cleanup")
        if self.user:
            try:
                account = pwd.getpwnam(self.username)
                require((account.pw_uid, account.pw_gid) == self.user,
                        "owned test account changed unexpectedly")
                command(["userdel", self.username], "remove owned test user")
            except (Failure, KeyError):
                errors.append("could not remove the owned test account")
        if self.group is not None:
            try:
                try:
                    group = grp.getgrnam(self.username)
                except KeyError:
                    group = None
                if group:
                    require(group.gr_gid == self.group, "owned test group changed unexpectedly")
                    command(["groupdel", self.username], "remove owned test group")
            except Failure:
                errors.append("could not remove the owned test group")
        for path in [*self.directories, *([self.area] if self.area else [])]:
            try:
                require(path.is_dir() and not path.is_symlink(), "owned directory changed unexpectedly")
                shutil.rmtree(path)
            except (Failure, OSError):
                errors.append("could not remove an owned test directory")
        return errors


def exercise(services, database, nats):
    credential = secrets.token_hex(32)
    admin_file = services.config / "hub-admin-token"
    database_file = services.config / "hub-database-url"
    enrollment_file = services.config / "enrollment-token"
    write_private(admin_file, credential + "\n", owner=services.user)
    write_private(database_file, database + "\n", owner=services.user)
    write_private(enrollment_file, credential + "\n")
    for path in (admin_file, database_file, enrollment_file):
        require(stat.S_IMODE(path.stat().st_mode) == 0o600, "fixture credential file is not private")
    # Reserve an unlistened port for the Scout-only outage: never stop NATS.
    with socket.socket() as offline_socket, socket.socket() as hub_socket:
        offline_socket.bind(("127.0.0.1", 0))
        hub_socket.bind(("127.0.0.1", 0))
        offline = "nats://127.0.0.1:" + str(offline_socket.getsockname()[1])
        bind = "127.0.0.1:" + str(hub_socket.getsockname()[1])
        base = "http://" + bind
        hub_values = {
            "SENTINEL_ADMIN_TOKEN_FILE": str(admin_file),
            "SENTINEL_DATABASE_URL_FILE": str(database_file),
            "SENTINEL_NATS_URL": nats, "SENTINEL_BIND": bind, "RUST_LOG": "warn",
        }
        # State/runtime defaults and Hub's web directory come from the actual
        # rendered units, not overrides that could mask broken packaged values.
        scout_values = {
            "SENTINEL_NATS_URL": nats, "SENTINEL_INTERVAL_SECONDS": "5",
            "SENTINEL_HOST_ROOT": str(services.host), "RUST_LOG": "warn",
        }
        write_private(services.env_files["hub"], environment_text(hub_values))
        write_private(services.env_files["scout"], environment_text(scout_values))
        scout = str(services.install / "scout/bin/scout")
        cli_env = clean_env() | scout_values | {
            "SENTINEL_STATE_DIR": str(services.states["scout"]),
            "SENTINEL_RUNTIME_MODE": "auto", "SENTINEL_HUB_URL": base,
            "SENTINEL_ASSET_NAME": "systemd-fictional-host",
        }

        def scout_cli(subcommand, *, enroll=False):
            env = cli_env | ({"SENTINEL_ADMIN_TOKEN_FILE": str(enrollment_file)} if enroll else {})
            result = command([scout, subcommand], "Scout " + subcommand, env=env, timeout=25)
            require(credential not in result.stdout + result.stderr,
                    "fixture credential leaked in Scout output")
            return json.loads(result.stdout)

        def change_scout_endpoint(endpoint):
            target = services.env_files["scout"]
            staged = target.with_suffix(".next")
            write_private(staged, environment_text(scout_values | {"SENTINEL_NATS_URL": endpoint}))
            os.replace(staged, target)

        command(["systemd-analyze", "verify", *[str(p) for p in services.units]],
                "verify actual rendered service units")
        command(["systemctl", "daemon-reload"], "load actual rendered service units")
        diagnostic = scout_cli("doctor")
        require(diagnostic["selected_mode"] == "native" and diagnostic["collection_allowed"]
                and diagnostic["host_root"] == str(services.host),
                "CI runtime/fixture doctor preflight failed")
        require(not (services.states["scout"] / "state.sqlite3").exists(),
                "doctor unexpectedly initialized state")
        hub_socket.close()
        services.action("start", "hub")
        wait_for(lambda: services.active("hub"), "actual Hub service activation")
        http = Http(base, credential)
        wait_for(http.ready, "real Hub database and JetStream readiness", timeout=90)
        http.get("/api/v1/assets", authenticated=False, expected=401, json_body=False)
        require(http.get("/api/v1/assets")["items"] == [], "fixture database is not empty")
        require(http.get("/api/v1/session")["mode"] == "development", "unexpected session mode")
        http.frontend(services.bundle)
        command([str(services.install / "hub/bin/hub"), "health"], "real Hub health command",
                env=clean_env() | {"SENTINEL_BIND": bind})
        initialized = scout_cli("init")
        require(initialized["asset_id"] is None, "test identity was already enrolled")
        scout_cli("enroll", enroll=True)
        # The resident unit never receives the enrollment credential or its path.
        enrollment_file.unlink()
        initial = scout_cli("status")
        identity = public_identity(initial)
        asset_id = initial["asset_id"]
        require(initial["installation_id"] == initialized["installation_id"]
                and initial["public_key"] == initialized["public_key"] and asset_id,
                "enrollment changed the persistent installation identity")
        require(stat.S_IMODE(services.states["scout"].stat().st_mode) == 0o700,
                "Scout state directory is not private")
        require(len(http.get("/api/v1/assets")["items"]) == 1, "enrollment did not create one asset")
        services.action("start", "scout")
        wait_for(lambda: services.active("scout"), "actual Scout service activation")
        first = wait_for(lambda: fixture_observation(http, asset_id), "daemon fixture ingestion")
        require(first["asset"]["metrics"]["process_count"] == 2, "unexpected fixture process count")
        require(public_identity(scout_cli("status")) == identity,
                "status under the active writer changed identity")
        require(services.active("hub") and services.active("scout"),
                "Hub and Scout cannot coexist as services")

        # Ensure at least one pending event exists before testing failure recovery.
        services.action("stop", "scout")
        change_scout_endpoint(offline)
        services.action("start", "scout")

        def queued():
            snapshot = queue_snapshot(services.states["scout"])
            return snapshot if snapshot[2] else None

        before = wait_for(queued, "offline queue persistence")
        previous = wait_for(lambda: services.active("scout"), "offline daemon activation")
        require(public_identity(scout_cli("status")) == identity, "offline daemon changed identity")
        # Exercise Restart=on-failure from the packaged unit; do not manually
        # start a replacement process and accidentally conceal a broken policy.
        command(["systemctl", "kill", "--kill-who=main", "--signal=SIGKILL", services.names["scout"]],
                "fail the owned Scout process")

        def restarted():
            current = services.active("scout")
            return current if current and current["MainPID"] != previous["MainPID"] and (
                int(current["NRestarts"]) > int(previous["NRestarts"])) else None

        wait_for(restarted, "packaged Scout automatic restart")

        def queue_survived():
            epoch, sequence, events = queue_snapshot(services.states["scout"])
            require(all(events.get(event) == value for event, value in before[2].items()),
                    "restart lost or changed a pending event ID/sequence/payload")
            return (epoch, sequence, events) if epoch > before[0] and sequence > before[1] else None

        after = wait_for(queue_survived, "post-restart collection with retained queue")
        status = scout_cli("status")
        require(public_identity(status) == identity and status["queue"]["pending_events"] >= len(before[2])
                and status["queue"]["overflow_count"] == 0, "restart changed identity or dropped the queue")
        change_scout_endpoint(nats)
        services.action("restart", "scout")
        wait_for(lambda: services.active("scout"), "explicit Scout restart after reconnection")
        wait_for(lambda: scout_cli("status")["queue"]["pending_events"] == 0, "durable queue replay")

        def newer_observation():
            detail = fixture_observation(http, asset_id)
            return detail if detail and detail["asset"]["metrics"]["sequence"] > after[1] else None

        wait_for(newer_observation, "new daemon observations after queue replay")
        require(public_identity(scout_cli("status")) == identity, "reconnection changed public identity")
        services.action("restart", "hub")
        wait_for(http.ready, "real Hub service restart")
        require(services.active("scout"), "restarting Hub disrupted Scout")
        require([item["id"] for item in http.get("/api/v1/assets")["items"]] == [asset_id],
                "service restart lost or duplicated the asset")
        http.frontend(services.bundle)
        require(public_identity(scout_cli("status")) == identity, "Hub restart changed Scout identity")
        # Capture only the two owned journals and inspect without printing their
        # contents; failure diagnostics below use static labels and service states.
        journal = command(["journalctl", "--no-pager", "--output=cat", "-u", services.names["hub"],
                           "-u", services.names["scout"]], "inspect fixture service logs")
        require(credential not in journal.stdout and database not in journal.stdout,
                "fixture credentials appeared in service logs")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path)
    args = parser.parse_args()
    services, failed = None, False
    try:
        # Keep this before any filesystem, account or systemd mutation. Setting
        # the CI flag alone never authorizes elevating a local invocation.
        require(os.geteuid() == 0 and os.environ.get("GITHUB_ACTIONS") == "true",
                "system service acceptance requires root on a fresh GitHub Actions runner")
        require(platform.system() == "Linux" and Path("/run/systemd/system").is_dir(),
                "a running system systemd manager is required")
        for executable in ("systemctl", "systemd-analyze", "journalctl", "useradd", "userdel", "groupdel"):
            require(shutil.which(executable, path=clean_env()["PATH"]), "missing system service test dependency")
        database = os.environ.get("TEST_DATABASE_URL", "postgres://sentinel:sentinel@127.0.0.1:5432/sentinel_native")
        nats = os.environ.get("TEST_NATS_URL", "nats://127.0.0.1:14228")
        checked_endpoints(database, nats)
        no_existing_installation()
        os.umask(0o077)

        def interrupted(_signum, _frame):
            raise Failure("system service acceptance was interrupted")

        signal.signal(signal.SIGTERM, interrupted)
        services = Services()
        services.prepare(args.bundle.resolve(strict=True))
        exercise(services, database, nats)
    except BaseException as error:
        failed = True
        # Generic exception text may contain URLs, response bodies or command
        # output. Only explicitly safe Failure messages are printed.
        reason = str(error) if isinstance(error, Failure) else type(error).__name__
        print("FAIL: systemd acceptance: " + reason, file=sys.stderr)
        if services:
            for component in services.names:
                try:
                    info = services.properties(component)
                    fields = ("LoadState", "ActiveState", "SubState", "Result", "ExecMainStatus")
                    print(component + ": " + ", ".join(key + "=" + info.get(key, "unknown")
                                                        for key in fields), file=sys.stderr)
                except Failure:
                    pass
    finally:
        if services:
            # A second cancellation must not interrupt our bounded, precisely
            # scoped teardown halfway through stopping the two owned services.
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            for error in services.cleanup():
                failed = True
                print("FAIL: cleanup: " + error, file=sys.stderr)
    if failed:
        return 1
    print("PASS: packaged Hub/Scout units, real authenticated API/frontend, fictional inventory, "
          "concurrent services/status, automatic failure recovery, stable identity and queued events, "
          "replay and explicit service restarts; owned resources cleaned")
    return 0


if __name__ == "__main__":
    sys.exit(main())
