#!/usr/bin/env python3
"""Tests for scripts/install-systemd.sh.

The installer is a Bash wrapper around a single embedded Python program
(``exec python3 - "$@" <<'PY' ... PY``).  These tests extract that embedded
source, import it as a module under a non-``__main__`` name, and exercise the
real logic with mocks and temporary directories.

Nothing here executes sudo/systemctl/useradd, binds a privileged port, opens a
network connection, or reads a real credential: every system-facing call is
mocked and every filesystem path is a temporary directory.
"""

import contextlib
import io
import json
import os
from pathlib import Path
import socket
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "scripts" / "install-systemd.sh"
START_MARKER = "<<'PY'\n"
END_MARKER = "\nPY"


def load_installer():
    """Return the embedded Python program as a module object."""
    text = INSTALLER.read_text(encoding="utf-8")
    start = text.index(START_MARKER) + len(START_MARKER)
    end = text.rindex(END_MARKER)
    source = text[start:end]
    module = types.ModuleType("install_systemd_embedded")
    module.__file__ = str(INSTALLER)
    exec(compile(source, str(INSTALLER), "exec"), module.__dict__)
    return module


M = load_installer()


def result(returncode=0, stdout="", stderr=""):
    return types.SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def elf_header(machine):
    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4] = 2  # 64-bit
    header[5] = 1  # little-endian
    header[6] = 1  # EV_CURRENT
    struct.pack_into("<H", header, 16, 2)  # ET_EXEC
    struct.pack_into("<H", header, 18, machine)
    return bytes(header)


def base_entries(version="v1.0.0", arch="amd64", machine=62):
    return [
        ("VERSION", (version + "\n").encode()),
        ("ARCH", (arch + "\n").encode()),
        ("bin/hub", elf_header(machine)),
        ("bin/scout", elf_header(machine)),
        ("web/dist/index.html", b"<!doctype html>"),
        ("deploy/systemd/sentinel-hub.service", b"[Unit]\nDescription=hub\n"),
        ("deploy/systemd/sentinel-scout.service", b"[Unit]\nDescription=scout\n"),
    ]


def write_archive(path, entries, fmt=tarfile.USTAR_FORMAT):
    with tarfile.open(path, "w:gz", format=fmt) as tar:
        for name, data in entries:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(data))


def raw_archive(path, members, fmt=tarfile.USTAR_FORMAT):
    """members: iterable of (TarInfo, bytes|None)."""
    with tarfile.open(path, "w:gz", format=fmt) as tar:
        for info, data in members:
            tar.addfile(info, io.BytesIO(data) if data is not None else None)


@contextlib.contextmanager
def linux_amd64():
    with mock.patch.object(M.platform, "system", return_value="Linux"), \
            mock.patch.object(M.platform, "machine", return_value="x86_64"):
        yield


class TempDirMixin:
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="sentinel-inst-test-")
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)

    def path(self, name):
        return self.tmp / name


class LoadedModule(unittest.TestCase):
    def test_embedded_program_is_loaded_without_running_main(self):
        self.assertNotEqual(M.__name__, "__main__")
        self.assertTrue(callable(M.main))
        self.assertTrue(issubclass(M.Failure, Exception))

    def test_no_shell_evaluation_surface(self):
        # The embedded program must not shell out through a shell.
        source = INSTALLER.read_text(encoding="utf-8")
        self.assertNotIn("shell=True", source)
        self.assertNotIn("os.system", source)
        self.assertNotIn("eval(", source)
        self.assertNotIn("exec(", source)


class EnvironmentText(unittest.TestCase):
    def test_simple_pair_is_quoted_with_trailing_newline(self):
        self.assertEqual(M.environment_text({"SENTINEL_NATS_URL": "nats://h:4222"}),
                         'SENTINEL_NATS_URL="nats://h:4222"\n')

    def test_quotes_and_backslashes_are_escaped(self):
        self.assertEqual(M.environment_text({"A_B": 'a"b\\c'}), 'A_B="a\\"b\\\\c"\n')

    def test_multiple_pairs_preserve_order(self):
        got = M.environment_text({"B_B": "2", "A_A": "1"})
        self.assertEqual(got, 'B_B="2"\nA_A="1"\n')

    def test_newline_is_rejected(self):
        with self.assertRaises(M.Failure):
            M.environment_text({"A_B": "line1\nline2"})

    def test_control_characters_are_rejected(self):
        for value in ("a\x00b", "a\x1fb", "a\x7fb", "a\tb"):
            with self.assertRaises(M.Failure):
                M.environment_text({"A_B": value})

    def test_invalid_variable_names_are_rejected(self):
        for key in ("lower", "1ABC", "A-B", "A B", ""):
            with self.assertRaises(M.Failure):
                M.environment_text({key: "x"})

    def test_non_string_values_are_stringified(self):
        self.assertEqual(M.environment_text({"A_B": 30}), 'A_B="30"\n')


class Endpoint(unittest.TestCase):
    def test_accepts_http_https_nats_tls(self):
        for value, schemes in (("http://hub.example", ("http", "https")),
                               ("https://hub.example:8443", ("http", "https")),
                               ("nats://nats.example:4222", ("nats", "tls")),
                               ("tls://nats.example:4222", ("nats", "tls")),
                               ("https://hub.example/", ("http", "https"))):
            parsed = M.endpoint(value, schemes)
            self.assertTrue(parsed.hostname, value)

    def test_rejects_userinfo(self):
        for value in ("http://user:pass@hub.example",
                      "http://user@hub.example",
                      "nats://token@nats.example:4222"):
            with self.assertRaises(M.Failure):
                M.endpoint(value, ("http", "https", "nats", "tls"))

    def test_rejects_query_fragment_and_path(self):
        for value in ("https://hub.example/?x=1",
                      "https://hub.example/#frag",
                      "https://hub.example/api"):
            with self.assertRaises(M.Failure):
                M.endpoint(value, ("http", "https"))

    def test_rejects_missing_host(self):
        with self.assertRaises(M.Failure):
            M.endpoint("http://", ("http", "https"))

    def test_rejects_port_zero_and_invalid_port(self):
        with self.assertRaises(M.Failure):
            M.endpoint("http://hub.example:0", ("http", "https"))
        with self.assertRaises(M.Failure):
            M.endpoint("http://hub.example:99999", ("http", "https"))

    def test_rejects_whitespace_backslash_and_control(self):
        for value in ("http://hub example", "http://hub\\example", "http://hub\n.example"):
            with self.assertRaises(M.Failure):
                M.endpoint(value, ("http", "https"))

    def test_rejects_unrequested_scheme(self):
        with self.assertRaises(M.Failure):
            M.endpoint("ftp://hub.example", ("http", "https"))


class ValidateBind(unittest.TestCase):
    def test_accepts_ipv4_and_bracketed_ipv6(self):
        M.validate_bind("127.0.0.1:8080")
        M.validate_bind("0.0.0.0:1")
        M.validate_bind("[::1]:8080")
        M.validate_bind("[::]:65535")

    def test_rejects_unbracketed_ipv6(self):
        with self.assertRaises(M.Failure):
            M.validate_bind("::1:8080")

    def test_rejects_bad_ports(self):
        for value in ("127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:-1", "127.0.0.1:abc"):
            with self.assertRaises(M.Failure):
                M.validate_bind(value)

    def test_rejects_non_ip_and_missing_port(self):
        for value in ("localhost:8080", "127.0.0.1", ":8080"):
            with self.assertRaises(M.Failure):
                M.validate_bind(value)


class CheckBindAvailable(unittest.TestCase):
    def listener(self):
        # `with socket.socket(...) as listener` needs __enter__ to yield itself.
        fake = mock.MagicMock()
        fake.__enter__.return_value = fake
        return fake

    def test_free_address_passes_and_binds_without_reuse(self):
        fake = self.listener()
        with mock.patch.object(M.socket, "socket", return_value=fake):
            M.check_bind_available("127.0.0.1:8080")
        fake.bind.assert_called_once_with(("127.0.0.1", 8080))
        self.assertFalse(fake.setsockopt.called)

    def test_occupied_address_is_rejected(self):
        fake = self.listener()
        fake.bind.side_effect = OSError("in use")
        with mock.patch.object(M.socket, "socket", return_value=fake):
            with self.assertRaises(M.Failure):
                M.check_bind_available("127.0.0.1:8080")

    def test_ipv6_uses_inet6_family_and_unbracketed_host(self):
        fake = self.listener()
        with mock.patch.object(M.socket, "socket", return_value=fake) as ctor:
            M.check_bind_available("[::1]:9000")
        self.assertEqual(ctor.call_args.args[0], socket.AF_INET6)
        fake.bind.assert_called_once_with(("::1", 9000))


class Arguments(unittest.TestCase):
    def install(self, component, *extra):
        base = ["--component", component, "--version", "v1.0.0",
                "--nats-url", "nats://n:4222"]
        if component == "hub":
            base += ["--database-url-file", "/tmp/db", "--admin-token-file", "/tmp/admin"]
        else:
            base += ["--hub-url", "https://h", "--enroll-token-file", "/tmp/e"]
        return M.arguments(base + list(extra))

    def test_arch_mapping_and_defaults(self):
        with linux_amd64():
            args = self.install("hub")
        self.assertEqual(args.arch, "amd64")
        self.assertEqual(args.machine, 62)
        self.assertEqual(args.mode, "install")
        self.assertEqual(args.runtime_mode, "auto")

    def test_arm64_mapping(self):
        with mock.patch.object(M.platform, "system", return_value="Linux"), \
                mock.patch.object(M.platform, "machine", return_value="aarch64"):
            args = self.install("scout")
        self.assertEqual(args.arch, "arm64")
        self.assertEqual(args.machine, 183)

    def test_unsupported_platform_is_rejected(self):
        with mock.patch.object(M.platform, "system", return_value="Linux"), \
                mock.patch.object(M.platform, "machine", return_value="ppc64le"):
            with self.assertRaises(M.Failure):
                M.arguments(["--component", "hub", "--version", "v1.0.0"])

    def test_version_format_is_enforced(self):
        with linux_amd64():
            for bad in ("1.0.0", "v1.0", "v1.0.0 "):
                with self.assertRaises(M.Failure):
                    M.arguments(["--component", "hub", "--version", bad])
            M.arguments(["--component", "hub", "--version", "v1.0.0-rc.1", "--verify-only"])

    def test_interval_bounds(self):
        with linux_amd64():
            for bad in ("4", "3601"):
                with self.assertRaises(M.Failure):
                    M.arguments(["--component", "hub", "--version", "v1.0.0", "--interval", bad])
            self.assertEqual(M.arguments(["--component", "hub", "--version", "v1.0.0",
                                          "--interval", "5", "--verify-only"]).interval, 5)

    def test_bind_is_validated(self):
        with linux_amd64():
            with self.assertRaises(M.Failure):
                M.arguments(["--component", "hub", "--version", "v1.0.0", "--bind", "bad"])

    def test_scout_rejects_hub_only_credentials(self):
        with linux_amd64():
            for flag in ("--database-url-file", "--admin-token-file"):
                with self.assertRaises(M.Failure):
                    M.arguments(["--component", "scout", "--version", "v1.0.0", flag, "/tmp/x"])

    def test_hub_rejects_scout_registration_arguments(self):
        with linux_amd64():
            for extra in (["--enroll-token-file", "/tmp/x"],
                          ["--asset-name", "host-1"],
                          ["--group-id", "00000000-0000-0000-0000-000000000000"]):
                with self.assertRaises(M.Failure):
                    M.arguments(["--component", "hub", "--version", "v1.0.0", *extra])

    def test_install_requires_component_specific_inputs(self):
        with linux_amd64():
            with self.assertRaises(M.Failure):
                M.arguments(["--component", "hub", "--version", "v1.0.0"])
            with self.assertRaises(M.Failure):
                M.arguments(["--component", "scout", "--version", "v1.0.0",
                             "--nats-url", "nats://n:4222"])
            # Scout needs hub-url and enroll token.
            args = M.arguments(["--component", "scout", "--version", "v1.0.0",
                                "--nats-url", "nats://n:4222",
                                "--hub-url", "https://h",
                                "--enroll-token-file", "/tmp/e"])
            self.assertEqual(args.mode, "install")

    def test_hub_install_requires_database_and_admin(self):
        with linux_amd64():
            with self.assertRaises(M.Failure):
                M.arguments(["--component", "hub", "--version", "v1.0.0",
                             "--nats-url", "nats://n:4222"])

    def test_group_id_must_be_uuid(self):
        with linux_amd64():
            with self.assertRaises(M.Failure):
                M.arguments(["--component", "scout", "--version", "v1.0.0",
                             "--verify-only", "--group-id", "not-a-uuid"])
            args = M.arguments(["--component", "scout", "--version", "v1.0.0",
                                "--verify-only",
                                "--group-id", "00000000-0000-0000-0000-000000000000"])
            self.assertEqual(args.group_id, "00000000-0000-0000-0000-000000000000")

    def test_asset_name_is_validated(self):
        with linux_amd64():
            with self.assertRaises(M.Failure):
                M.arguments(["--component", "scout", "--version", "v1.0.0",
                             "--verify-only", "--asset-name", "bad name"])
            args = M.arguments(["--component", "scout", "--version", "v1.0.0",
                                "--verify-only", "--asset-name", "host-1.example_2"])
            self.assertEqual(args.asset_name, "host-1.example_2")

    def test_url_credentials_are_rejected_during_parsing(self):
        with linux_amd64():
            with self.assertRaises(M.Failure):
                M.arguments(["--component", "scout", "--version", "v1.0.0",
                             "--hub-url", "https://user:pass@h"])
            with self.assertRaises(M.Failure):
                M.arguments(["--component", "scout", "--version", "v1.0.0",
                             "--nats-url", "nats://user:pass@n:4222"])

    def test_fetch_only_requires_output_dir_and_vice_versa(self):
        with linux_amd64():
            with self.assertRaises(M.Failure):
                M.arguments(["--component", "hub", "--version", "v1.0.0", "--fetch-only"])
            with self.assertRaises(M.Failure):
                M.arguments(["--component", "hub", "--version", "v1.0.0",
                             "--output-dir", "/tmp/out"])

    def test_install_modes_are_mutually_exclusive(self):
        with linux_amd64():
            with self.assertRaises(SystemExit):
                M.arguments(["--component", "hub", "--version", "v1.0.0",
                             "--plan", "--dry-run"])

    def test_mode_flags_map_to_mode_names(self):
        with linux_amd64():
            for flag, mode in (("--plan", "plan"), ("--dry-run", "dry_run"),
                               ("--verify-only", "verify_only")):
                args = M.arguments(["--component", "hub", "--version", "v1.0.0", flag])
                self.assertEqual(args.mode, mode)
            args = M.arguments(["--component", "hub", "--version", "v1.0.0",
                                "--fetch-only", "--output-dir", "/tmp/out"])
            self.assertEqual(args.mode, "fetch_only")

class RunHelper(unittest.TestCase):
    def test_clean_base_env_plus_overrides(self):
        recorded = {}

        def fake(cmd, *, env=None, capture_output=None, text=None, timeout=None):
            recorded.update(cmd=list(cmd), env=dict(env), timeout=timeout)
            return result()

        with mock.patch.object(M.subprocess, "run", fake):
            M.run(["true"], "标签", env={"TUF_ROOT": "/p"})
        self.assertEqual(recorded["env"], M.BASE_ENV | {"TUF_ROOT": "/p"})
        self.assertNotIn("HOME", recorded["env"])
        self.assertEqual(recorded["cmd"], ["true"])

    def test_nonzero_exit_fails_without_echoing_output(self):
        with mock.patch.object(M.subprocess, "run",
                               return_value=result(1, stdout="SECRET-OUT", stderr="SECRET-ERR")):
            with self.assertRaises(M.Failure) as ctx:
                M.run(["x"], "检查服务")
        self.assertIn("检查服务", str(ctx.exception))
        self.assertNotIn("SECRET", str(ctx.exception))

    def test_check_false_returns_result_even_on_failure(self):
        with mock.patch.object(M.subprocess, "run", return_value=result(7, stdout="x")):
            got = M.run(["x"], "label", check=False)
        self.assertEqual(got.returncode, 7)

    def test_missing_program_or_timeout_fails(self):
        with mock.patch.object(M.subprocess, "run", side_effect=FileNotFoundError()):
            with self.assertRaises(M.Failure):
                M.run(["x"], "label")
        with mock.patch.object(M.subprocess, "run", side_effect=subprocess.TimeoutExpired("x", 1)):
            with self.assertRaises(M.Failure):
                M.run(["x"], "label")


class PrivateBytes(TempDirMixin, unittest.TestCase):
    def write(self, data, mode=0o600, name="cred"):
        p = self.path(name)
        p.write_bytes(data)
        os.chmod(p, mode)
        return p

    def test_accepts_private_regular_file(self):
        p = self.write(b"secret-token\r\n")
        self.assertEqual(M.private_bytes(p), b"secret-token\r\n")

    def test_accepts_owner_read_only(self):
        self.assertEqual(M.private_bytes(self.write(b"x", mode=0o400)), b"x")

    def test_rejects_group_or_other_access(self):
        for mode in (0o640, 0o604, 0o644, 0o677):
            with self.assertRaises(M.Failure, msg=oct(mode)):
                M.private_bytes(self.write(b"secret", mode=mode, name="c-%o" % mode))

    def test_rejects_symlink_without_following(self):
        target = self.write(b"secret", name="real")
        link = self.path("link")
        link.symlink_to(target)
        with self.assertRaises(OSError):
            M.private_bytes(link)

    def test_rejects_directory(self):
        directory = self.path("dir")
        directory.mkdir()
        os.chmod(directory, 0o700)
        with self.assertRaises(OSError):
            M.private_bytes(directory)

    def test_rejects_empty_and_blank(self):
        for index, data in enumerate((b"", b"\n", b"\r\n")):
            with self.assertRaises(M.Failure):
                M.private_bytes(self.write(data, name="blank-%d" % index))

    def test_rejects_nul_and_non_utf8(self):
        for index, data in enumerate((b"a\x00b", b"\xff\xfeabc")):
            with self.assertRaises(M.Failure):
                M.private_bytes(self.write(data, name="bad-%d" % index))

    def test_size_limit_is_16384(self):
        self.assertEqual(len(M.private_bytes(self.write(b"a" * 16384, name="max"))), 16384)
        with self.assertRaises(M.Failure):
            M.private_bytes(self.write(b"a" * 16385, name="over"))


class WriteFile(TempDirMixin, unittest.TestCase):
    def test_default_mode_is_0600(self):
        p = self.path("f")
        M.write_file(p, b"data")
        self.assertEqual(p.read_bytes(), b"data")
        self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)

    def test_explicit_mode_is_not_limited_by_umask(self):
        old = os.umask(0o077)
        try:
            for mode in (0o600, 0o644, 0o700, 0o640):
                p = self.path("f-%o" % mode)
                M.write_file(p, b"x", mode=mode)
                self.assertEqual(stat.S_IMODE(p.stat().st_mode), mode, oct(mode))
        finally:
            os.umask(old)

    def test_str_is_encoded(self):
        p = self.path("f")
        M.write_file(p, "héllo")
        self.assertEqual(p.read_bytes(), "héllo".encode())

    def test_exclusive_create_refuses_overwrite(self):
        p = self.path("f")
        M.write_file(p, b"one")
        with self.assertRaises(FileExistsError):
            M.write_file(p, b"two")
        self.assertEqual(p.read_bytes(), b"one")

    def test_symlink_is_not_followed(self):
        target = self.path("target")
        target.write_bytes(b"original")
        link = self.path("link")
        link.symlink_to(target)
        with self.assertRaises(OSError):
            M.write_file(link, b"overwrite")
        self.assertEqual(target.read_bytes(), b"original")


class Acquire(TempDirMixin, unittest.TestCase):
    def args(self, **over):
        base = dict(version="v1.2.3", arch="amd64", local_bundle=None)
        base.update(over)
        return types.SimpleNamespace(**base)

    def make_run(self, fail_labels=()):
        calls = []

        def fake(argv, label, *, env=None, timeout=90, check=True):
            calls.append({"argv": [str(a) for a in argv], "label": label,
                          "env": dict(env or {}), "timeout": timeout})
            if label in fail_labels:
                raise M.Failure(label + "失败")
            return result()

        return fake, calls

    def make_download(self, recorded):
        def fake(url, target, limit):
            recorded.append(url)
            target.write_bytes(b"content")
        return fake

    def test_verify_blob_uses_exact_identity_and_private_tuf(self):
        run, calls = self.make_run()
        urls = []
        with mock.patch.object(M, "run", run), mock.patch.object(M, "download", self.make_download(urls)):
            archive, signature = M.acquire(self.args(), self.tmp)
        name = "sentinel-v1.2.3-linux-amd64.tar.gz"
        self.assertEqual(urls, [M.REPOSITORY + "/releases/download/v1.2.3/" + name,
                                M.REPOSITORY + "/releases/download/v1.2.3/" + name + ".sigstore.json"])
        verify = next(c for c in calls if c["argv"][:2] == ["cosign", "verify-blob"])
        self.assertEqual(verify["argv"], [
            "cosign", "verify-blob", "--bundle", str(signature),
            "--certificate-identity", M.IDENTITY + "@refs/tags/v1.2.3",
            "--certificate-oidc-issuer", M.ISSUER, str(archive)])
        self.assertEqual(verify["env"], {"TUF_ROOT": str(self.tmp / "cosign-tuf")})
        self.assertNotIn("HOME", verify["env"])
        tuf = self.tmp / "cosign-tuf"
        self.assertTrue(tuf.is_dir())
        self.assertEqual(stat.S_IMODE(tuf.stat().st_mode), 0o700)
        joined = " ".join(" ".join(c["argv"]) for c in calls)
        self.assertNotIn("regexp", joined)
        self.assertNotIn("insecure-ignore-tlog", joined)

    def test_verify_failure_aborts_before_any_extract_or_install(self):
        run, calls = self.make_run(fail_labels={"原生归档签名验证"})
        urls = []
        with mock.patch.object(M, "run", run), mock.patch.object(M, "download", self.make_download(urls)):
            with self.assertRaises(M.Failure):
                M.acquire(self.args(), self.tmp)
        self.assertEqual(len(urls), 2)  # archive and signature were fetched first

    def test_local_bundle_skips_cosign_and_signature(self):
        local = self.path("local.tar.gz")
        local.write_bytes(b"local-bytes")
        run = mock.MagicMock(side_effect=AssertionError("cosign must not run for local bundles"))
        with mock.patch.object(M, "run", run):
            archive, signature = M.acquire(self.args(local_bundle=local), self.tmp)
        self.assertIsNone(signature)
        self.assertEqual(archive.read_bytes(), b"local-bytes")
        self.assertFalse(run.called)


class InspectArchive(TempDirMixin, unittest.TestCase):
    def make(self, entries=None, name="bundle.tar.gz"):
        p = self.path(name)
        write_archive(p, entries if entries is not None else base_entries())
        return p

    def test_valid_archive_passes(self):
        M.inspect_archive(self.make(), "v1.0.0", "amd64", 62)

    def test_version_and_arch_must_match(self):
        with self.assertRaises(M.Failure):
            M.inspect_archive(self.make(base_entries(version="v2.0.0")), "v1.0.0", "amd64", 62)
        with self.assertRaises(M.Failure):
            M.inspect_archive(self.make(base_entries(arch="arm64", machine=183)), "v1.0.0", "amd64", 62)

    def test_missing_required_file_is_rejected(self):
        entries = [e for e in base_entries() if e[0] != "web/dist/index.html"]
        with self.assertRaises(M.Failure):
            M.inspect_archive(self.make(entries), "v1.0.0", "amd64", 62)

    def test_files_outside_layout_are_rejected(self):
        entries = base_entries() + [("etc/passwd", b"x")]
        with self.assertRaises(M.Failure):
            M.inspect_archive(self.make(entries), "v1.0.0", "amd64", 62)

    def test_extra_web_assets_are_allowed(self):
        entries = base_entries() + [("web/dist/app.js", b"js")]
        M.inspect_archive(self.make(entries), "v1.0.0", "amd64", 62)

    def test_absolute_traversal_dot_and_backslash_paths_are_rejected(self):
        for index, bad in enumerate(("/etc/passwd", "../evil", "bin/./hub", "bin\\hub", "a//b")):
            info = tarfile.TarInfo(bad)
            info.size = 0
            p = self.path("bad-%d.tar.gz" % index)
            raw_archive(p, [(info, b"")])
            with self.assertRaises(M.Failure, msg=bad):
                M.inspect_archive(p, "v1.0.0", "amd64", 62)

    def test_duplicate_names_are_rejected(self):
        entries = base_entries() + [("VERSION", b"v1.0.0\n")]
        p = self.path("dup.tar.gz")
        write_archive(p, entries)
        with self.assertRaises(M.Failure):
            M.inspect_archive(p, "v1.0.0", "amd64", 62)

    def test_symlink_directory_and_hardlink_members_are_rejected(self):
        for kind in (tarfile.SYMTYPE, tarfile.DIRTYPE, tarfile.LNKTYPE):
            info = tarfile.TarInfo("web/dist/x")
            info.type = kind
            if kind == tarfile.SYMTYPE:
                info.linkname = "index.html"
            if kind == tarfile.LNKTYPE:
                info.linkname = "web/dist/index.html"
            p = self.path("special-%s.tar.gz" % kind.decode())
            raw_archive(p, [(info, None)])
            with self.assertRaises(M.Failure, msg=str(kind)):
                M.inspect_archive(p, "v1.0.0", "amd64", 62)

    def test_pax_header_member_is_rejected(self):
        info = tarfile.TarInfo("web/dist/app.js")
        info.size = 1
        info.pax_headers = {"comment": "x"}
        p = self.path("pax.tar.gz")
        raw_archive(p, [(info, b"x")], fmt=tarfile.PAX_FORMAT)
        with self.assertRaises(M.Failure):
            M.inspect_archive(p, "v1.0.0", "amd64", 62)

    def test_binary_must_be_native_elf64_for_architecture(self):
        cases = (("short", b"\x7fELF"),
                 ("not-elf", b"MZ" + b"\x00" * 62),
                 ("wrong-class", b"\x7fELF\x01\x01" + b"\x00" * 58))
        for label, data in cases:
            entries = [(n, data if n == "bin/hub" else v) for n, v in base_entries()]
            with self.assertRaises(M.Failure, msg=label):
                M.inspect_archive(self.make(entries, name=label + ".tar.gz"), "v1.0.0", "amd64", 62)
        entries = base_entries(machine=183)
        with self.assertRaises(M.Failure):
            M.inspect_archive(self.make(entries, name="machine.tar.gz"), "v1.0.0", "amd64", 62)

    def test_empty_unit_and_oversize_metadata_are_rejected(self):
        entries = [(n, b"" if n.endswith(".service") else v) for n, v in base_entries()]
        with self.assertRaises(M.Failure):
            M.inspect_archive(self.make(entries, name="empty-unit.tar.gz"), "v1.0.0", "amd64", 62)
        entries = [(n, b"x" * 200 if n == "VERSION" else v) for n, v in base_entries()]
        with self.assertRaises(M.Failure):
            M.inspect_archive(self.make(entries, name="long-version.tar.gz"), "v1.0.0", "amd64", 62)


class ExtractArchive(TempDirMixin, unittest.TestCase):
    def test_extracts_validated_files_with_expected_modes(self):
        archive = self.path("bundle.tar.gz")
        write_archive(archive, base_entries())
        dest = self.path("bundle")
        old = os.umask(0o077)
        try:
            M.extract_archive(archive, dest)
        finally:
            os.umask(old)
        self.assertEqual(stat.S_IMODE(dest.stat().st_mode), 0o700)
        self.assertEqual((dest / "bin/hub").read_bytes(), elf_header(62))
        self.assertEqual(stat.S_IMODE((dest / "bin/hub").stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE((dest / "bin/scout").stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE((dest / "VERSION").stat().st_mode), 0o644)
        self.assertEqual(stat.S_IMODE((dest / "web" / "dist").stat().st_mode), 0o755)
        self.assertEqual((dest / "web" / "dist" / "index.html").read_bytes(), b"<!doctype html>")
        self.assertFalse((dest / "bin").is_symlink())


class FreshInstall(TempDirMixin, unittest.TestCase):
    def paths(self):
        return {"install": self.path("opt/install"),
                "config": self.path("etc/config"),
                "state": self.path("var/state"),
                "unit": self.path("etc/unit.service")}

    def run_not_found(self, stdout="not-found\n"):
        def fake(argv, label, *, env=None, timeout=90, check=True):
            return result(stdout=stdout)
        return fake

    def test_empty_paths_and_not_loaded_service_pass(self):
        with mock.patch.object(M.os.path, "lexists", side_effect=lambda p: False), \
                mock.patch.object(M, "run", self.run_not_found()):
            M.fresh_install("scout", self.paths())

    def test_existing_install_path_is_rejected(self):
        existing = self.paths()["state"]
        with mock.patch.object(M.os.path, "lexists",
                               side_effect=lambda p: str(p) == str(existing)), \
                mock.patch.object(M, "run", self.run_not_found()):
            with self.assertRaises(M.Failure):
                M.fresh_install("scout", self.paths())

    def test_existing_systemd_unit_is_rejected(self):
        with mock.patch.object(M.os.path, "lexists",
                               side_effect=lambda p: str(p).endswith("/etc/systemd/system/sentinel-hub.service")), \
                mock.patch.object(M, "run", self.run_not_found()):
            with self.assertRaises(M.Failure):
                M.fresh_install("hub", self.paths())

    def test_loaded_service_is_rejected(self):
        with mock.patch.object(M.os.path, "lexists", side_effect=lambda p: False), \
                mock.patch.object(M, "run", self.run_not_found(stdout="loaded\n")):
            with self.assertRaises(M.Failure):
                M.fresh_install("scout", self.paths())

    def test_existing_hub_account_is_rejected(self):
        with mock.patch.object(M.os.path, "lexists", side_effect=lambda p: False), \
                mock.patch.object(M, "run", self.run_not_found()), \
                mock.patch.object(M.pwd, "getpwnam",
                                  return_value=types.SimpleNamespace(pw_uid=1, pw_gid=1)), \
                mock.patch.object(M.grp, "getgrnam", side_effect=KeyError):
            with self.assertRaises(M.Failure):
                M.fresh_install("hub", self.paths())

    def test_absent_hub_account_and_group_pass(self):
        with mock.patch.object(M.os.path, "lexists", side_effect=lambda p: False), \
                mock.patch.object(M, "run", self.run_not_found()), \
                mock.patch.object(M.pwd, "getpwnam", side_effect=KeyError), \
                mock.patch.object(M.grp, "getgrnam", side_effect=KeyError):
            M.fresh_install("hub", self.paths())

    def test_scout_never_consults_accounts(self):
        with mock.patch.object(M.os.path, "lexists", side_effect=lambda p: False), \
                mock.patch.object(M, "run", self.run_not_found()), \
                mock.patch.object(M.pwd, "getpwnam", side_effect=AssertionError("passwd consulted")), \
                mock.patch.object(M.grp, "getgrnam", side_effect=AssertionError("group consulted")):
            M.fresh_install("scout", self.paths())


class Doctor(unittest.TestCase):
    def call(self, rc=0, stdout="", mode="native"):
        recorded = {}

        def fake(argv, label, *, env=None, timeout=90, check=True):
            recorded.update(argv=[str(a) for a in argv], env=dict(env or {}), check=check)
            return result(rc, stdout)

        with mock.patch.object(M, "run", fake):
            error = None
            try:
                M.doctor(Path("/tmp/scout"), mode)
            except M.Failure as exc:
                error = exc
        return error, recorded

    def test_native_allowed_passes_with_mode_env(self):
        error, rec = self.call(stdout=json.dumps({"selected_mode": "native", "collection_allowed": True}))
        self.assertIsNone(error)
        self.assertEqual(rec["env"], {"SENTINEL_RUNTIME_MODE": "native"})
        self.assertEqual(rec["argv"], ["/tmp/scout", "doctor"])
        self.assertFalse(rec["check"])

    def test_unknown_and_container_modes_are_rejected(self):
        for mode in ("unknown", "container"):
            error, _ = self.call(stdout=json.dumps({"selected_mode": mode, "collection_allowed": True}))
            self.assertIsNotNone(error, mode)

    def test_collection_not_allowed_is_rejected(self):
        error, _ = self.call(stdout=json.dumps({"selected_mode": "native", "collection_allowed": False}))
        self.assertIsNotNone(error)

    def test_nonzero_exit_is_rejected(self):
        error, _ = self.call(rc=1, stdout=json.dumps({"selected_mode": "native", "collection_allowed": True}))
        self.assertIsNotNone(error)

    def test_invalid_and_non_object_json_are_rejected(self):
        for stdout in ("not json", "", "[]", "null", "3"):
            error, _ = self.call(stdout=stdout)
            self.assertIsNotNone(error, stdout)

    def test_runtime_mode_is_forwarded(self):
        _, rec = self.call(stdout=json.dumps({"selected_mode": "native", "collection_allowed": True}),
                           mode="auto")
        self.assertEqual(rec["env"], {"SENTINEL_RUNTIME_MODE": "auto"})


class ServiceState(unittest.TestCase):
    def test_parses_properties(self):
        stdout = "MainPID=4242\nNRestarts=0\nActiveState=active\nSubState=running\n"
        with mock.patch.object(M, "run", return_value=result(0, stdout)):
            self.assertEqual(M.service_state("sentinel-hub.service"),
                             {"MainPID": "4242", "NRestarts": "0",
                              "ActiveState": "active", "SubState": "running"})

    def test_run_failure_returns_empty_mapping(self):
        with mock.patch.object(M, "run", return_value=result(1)):
            self.assertEqual(M.service_state("sentinel-hub.service"), {})


class HubSession(unittest.TestCase):
    class Response:
        def __init__(self, body, status=200):
            self.body = body
            self.status = status

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self, n=-1):
            return self.body if n is None or n < 0 else self.body[:n]

    def session(self, *, bind="127.0.0.1:8080", body=b"", status=200, error=None, token=b"t" * 40):
        opener = mock.MagicMock()
        if error is not None:
            opener.open.side_effect = error
        else:
            opener.open.return_value = self.Response(body, status)
        captured = {}

        def build(*handlers):
            captured["handlers"] = handlers
            return opener

        with mock.patch.object(M, "private_bytes", return_value=token), \
                mock.patch.object(M.urllib.request, "build_opener", build):
            outcome = M.hub_session(types.SimpleNamespace(bind=bind),
                                    {"config": Path("/tmp/nonexistent")})
        request = opener.open.call_args.args[0]
        return outcome, request, captured["handlers"]

    def admin_body(self, **over):
        payload = {"role": "admin", "authentication": "administrator_token"}
        payload.update(over)
        return json.dumps(payload).encode()

    def test_admin_session_against_loopback(self):
        outcome, request, _ = self.session(body=self.admin_body())
        self.assertTrue(outcome)
        self.assertEqual(request.full_url, "http://127.0.0.1:8080/api/v1/session")
        self.assertEqual(request.headers["Authorization"], "Bearer " + "t" * 40)

    def test_proxies_disabled_and_redirects_refused(self):
        _, _, handlers = self.session(body=self.admin_body())
        proxy, redirect = handlers[0], handlers[1]
        self.assertEqual(proxy.proxies, {})
        self.assertIsNone(redirect.redirect_request(None, None, 302, "Found", {}, "http://evil"))

    def test_unspecified_bind_probes_loopback(self):
        _, request, _ = self.session(bind="0.0.0.0:9001", body=self.admin_body())
        self.assertEqual(request.full_url, "http://127.0.0.1:9001/api/v1/session")

    def test_ipv6_unspecified_bind_probes_v6_loopback(self):
        _, request, _ = self.session(bind="[::]:9002", body=self.admin_body())
        self.assertEqual(request.full_url, "http://[::1]:9002/api/v1/session")

    def test_wrong_role_or_auth_is_rejected(self):
        for body in (json.dumps({"role": "viewer", "authentication": "administrator_token"}).encode(),
                     json.dumps({"role": "admin", "authentication": "password"}).encode(),
                     json.dumps({}).encode()):
            outcome, _, _ = self.session(body=body)
            self.assertFalse(outcome, body)

    def test_non_200_oversize_and_bad_json_are_false(self):
        for kwargs in ({"body": self.admin_body(), "status": 503},
                       {"body": b"x" * 5000},
                       {"body": b"not json"}):
            outcome, _, _ = self.session(**kwargs)
            self.assertFalse(outcome, kwargs)

    def test_connection_error_is_false(self):
        outcome, _, _ = self.session(error=OSError("connection refused"))
        self.assertFalse(outcome)


class WaitHealthy(unittest.TestCase):
    def hub_state(self, **over):
        base = {"MainPID": "4242", "NRestarts": "0",
                "ActiveState": "active", "SubState": "running"}
        base.update(over)
        return base

    def hub_run(self, health=(0, 0)):
        counter = {"n": 0}

        def fake(argv, label, *, env=None, timeout=90, check=True):
            argv = [str(a) for a in argv]
            if argv[:2] == ["systemctl", "is-active"]:
                return result(0)
            if argv[-1] == "health":
                index = counter["n"]
                counter["n"] += 1
                return result(health[index] if index < len(health) else health[-1])
            return result(0)

        return fake

    def hub(self, states, run, session=True):
        states = list(states)
        return mock.patch.multiple(
            M, run=run,
            service_state=mock.MagicMock(side_effect=lambda s: states.pop(0)),
            hub_session=mock.MagicMock(return_value=session))

    def test_hub_success_requires_stable_pid_and_credentials(self):
        sleep = mock.MagicMock()
        with self.hub([self.hub_state()] * 3, self.hub_run()), \
                mock.patch.object(M.time, "sleep", sleep):
            M.wait_healthy(types.SimpleNamespace(component="hub", bind="127.0.0.1:8080"),
                           M.paths_for("hub"), {})
        self.assertTrue(any(c.args and c.args[0] == 3 for c in sleep.call_args_list))

    def test_hub_restart_count_blocks_success(self):
        with self.hub([self.hub_state(NRestarts="1")] * 31, self.hub_run()), \
                mock.patch.object(M.time, "sleep", mock.MagicMock()):
            with self.assertRaises(M.Failure):
                M.wait_healthy(types.SimpleNamespace(component="hub", bind="127.0.0.1:8080"),
                               M.paths_for("hub"), {})

    def test_hub_pid_change_between_probes_is_rejected(self):
        states = [self.hub_state(MainPID="4242"), self.hub_state(MainPID="5000")]
        states += [self.hub_state(MainPID="5000")] * 30
        with self.hub(states, self.hub_run()), \
                mock.patch.object(M.time, "sleep", mock.MagicMock()):
            with self.assertRaises(M.Failure):
                M.wait_healthy(types.SimpleNamespace(component="hub", bind="127.0.0.1:8080"),
                               M.paths_for("hub"), {})

    def test_hub_auth_rejection_never_reports_ready(self):
        with self.hub([self.hub_state()] * 31, self.hub_run(), session=False), \
                mock.patch.object(M.time, "sleep", mock.MagicMock()):
            with self.assertRaises(M.Failure):
                M.wait_healthy(types.SimpleNamespace(component="hub", bind="127.0.0.1:8080"),
                               M.paths_for("hub"), {})

    def test_hub_second_probe_failure_never_reports_ready(self):
        with self.hub([self.hub_state()] * 31, self.hub_run(health=(0, 1))), \
                mock.patch.object(M.time, "sleep", mock.MagicMock()):
            with self.assertRaises(M.Failure):
                M.wait_healthy(types.SimpleNamespace(component="hub", bind="127.0.0.1:8080"),
                               M.paths_for("hub"), {})

    def test_hub_inactive_service_never_reports_ready(self):
        def fake(argv, label, *, env=None, timeout=90, check=True):
            return result(1)

        with mock.patch.object(M, "run", fake), \
                mock.patch.object(M.time, "sleep", mock.MagicMock()):
            with self.assertRaises(M.Failure):
                M.wait_healthy(types.SimpleNamespace(component="hub", bind="127.0.0.1:8080"),
                               M.paths_for("hub"), {})

    def scout_run(self, asset=True, restarts="0"):
        def fake(argv, label, *, env=None, timeout=90, check=True):
            argv = [str(a) for a in argv]
            if argv[0] == "systemctl" and argv[1] == "is-active":
                return result(0)
            if argv[0] == "systemctl" and argv[1] == "show":
                return result(0, stdout=restarts + "\n")
            if argv[-1] == "status":
                return result(0, stdout=json.dumps({"asset_id": "abc"} if asset else {}))
            return result(0)

        return fake

    def test_scout_success(self):
        sleep = mock.MagicMock()
        with mock.patch.object(M, "run", self.scout_run()), \
                mock.patch.object(M.time, "sleep", sleep):
            M.wait_healthy(types.SimpleNamespace(component="scout"), M.paths_for("scout"), {})
        self.assertTrue(any(c.args and c.args[0] == 3 for c in sleep.call_args_list))

    def test_scout_unregistered_is_not_ready(self):
        with mock.patch.object(M, "run", self.scout_run(asset=False)), \
                mock.patch.object(M.time, "sleep", mock.MagicMock()):
            with self.assertRaises(M.Failure) as ctx:
                M.wait_healthy(types.SimpleNamespace(component="scout"), M.paths_for("scout"), {})
        self.assertIn("尚未登记", str(ctx.exception))

    def test_scout_restarts_block_success(self):
        with mock.patch.object(M, "run", self.scout_run(restarts="1")), \
                mock.patch.object(M.time, "sleep", mock.MagicMock()):
            with self.assertRaises(M.Failure):
                M.wait_healthy(types.SimpleNamespace(component="scout"), M.paths_for("scout"), {})


class ResidentValues(unittest.TestCase):
    def args(self, component, **over):
        base = dict(component=component, nats_url="nats://n:4222",
                    nats_token_file=Path("/tmp/nats"), hub_url="https://hub.example",
                    runtime_mode="native", interval=30, bind="127.0.0.1:8080",
                    enroll_token_file=Path("/tmp/enroll"))
        base.update(over)
        return types.SimpleNamespace(**base)

    def test_scout_never_persists_enroll_admin_credential(self):
        paths = M.paths_for("scout")
        values = M.resident_values(self.args("scout"), paths)
        self.assertNotIn("SENTINEL_ADMIN_TOKEN_FILE", values)
        self.assertNotIn("SENTINEL_HUB_URL", values)
        self.assertEqual(values["SENTINEL_NATS_TOKEN_FILE"], str(paths["config"] / "nats-token"))
        text = M.environment_text(values)
        self.assertNotIn("/tmp/enroll", text)
        self.assertNotIn("admin-token", text)

    def test_scout_native_keys(self):
        paths = M.paths_for("scout")
        values = M.resident_values(self.args("scout"), paths)
        self.assertEqual(values["SENTINEL_RUNTIME_MODE"], "native")
        self.assertEqual(values["SENTINEL_STATE_DIR"], str(paths["state"]))
        self.assertEqual(values["SENTINEL_NETWORK_PROC_PREFIX"], "proc/1/net")
        self.assertEqual(values["SENTINEL_INTERVAL_SECONDS"], "30")

    def test_hub_keys_and_paths(self):
        paths = M.paths_for("hub")
        values = M.resident_values(self.args("hub"), paths)
        self.assertEqual(values["SENTINEL_DATABASE_URL_FILE"], str(paths["config"] / "database-url"))
        self.assertEqual(values["SENTINEL_ADMIN_TOKEN_FILE"], str(paths["config"] / "admin-token"))
        self.assertEqual(values["SENTINEL_WEB_DIR"], str(paths["install"] / "web/dist"))
        self.assertEqual(values["SENTINEL_BIND"], "127.0.0.1:8080")

    def test_missing_nats_token_omits_key(self):
        values = M.resident_values(self.args("scout", nats_token_file=None), M.paths_for("scout"))
        self.assertNotIn("SENTINEL_NATS_TOKEN_FILE", values)


class Credentials(unittest.TestCase):
    def connect(self):
        calls = []

        def fake(host, port, label):
            calls.append((host, port, label))

        return fake, calls

    def args(self, component, **over):
        base = dict(component=component, nats_url="nats://nats.example:4222",
                    hub_url="https://hub.example", nats_token_file=None,
                    database_url_file=None, admin_token_file=None, enroll_token_file=None)
        base.update(over)
        return types.SimpleNamespace(**base)

    def test_hub_reads_private_credentials_and_checks_dependencies(self):
        connect, calls = self.connect()
        values = {Path("/db"): b"postgres://user@pg.example:5432/sentinel",
                  Path("/admin"): b"a" * 40}
        with mock.patch.object(M, "private_bytes", side_effect=lambda p: values[p]), \
                mock.patch.object(M, "check_connection", connect):
            creds = M.credentials_and_connections(
                self.args("hub", database_url_file=Path("/db"), admin_token_file=Path("/admin")))
        self.assertEqual(creds["database_url"], values[Path("/db")])
        self.assertEqual(calls, [("nats.example", 4222, "NATS"), ("pg.example", 5432, "PostgreSQL")])

    def test_short_admin_token_is_rejected(self):
        with mock.patch.object(M, "private_bytes", return_value=b"short"), \
                mock.patch.object(M, "check_connection", mock.MagicMock()):
            with self.assertRaises(M.Failure):
                M.credentials_and_connections(
                    self.args("hub", database_url_file=Path("/db"), admin_token_file=Path("/admin")))

    def test_database_url_must_be_postgres_with_host_and_name(self):
        for url in (b"not-a-url", b"mysql://h/db", b"postgres:///db",
                    b"postgres://h/", b"postgres://h"):
            with mock.patch.object(M, "private_bytes", return_value=url), \
                    mock.patch.object(M, "check_connection", mock.MagicMock()):
                with self.assertRaises(M.Failure, msg=url):
                    M.credentials_and_connections(
                        self.args("hub", database_url_file=Path("/db"),
                                  admin_token_file=Path("/admin")))

    def test_scout_uses_enroll_token_and_checks_hub(self):
        connect, calls = self.connect()
        with mock.patch.object(M, "private_bytes", return_value=b"e" * 40), \
                mock.patch.object(M, "check_connection", connect):
            creds = M.credentials_and_connections(
                self.args("scout", enroll_token_file=Path("/enroll")))
        self.assertEqual(creds["enroll_token"], b"e" * 40)
        self.assertEqual(calls, [("nats.example", 4222, "NATS"), ("hub.example", 443, "Hub")])


class Fetch(TempDirMixin, unittest.TestCase):
    def test_copies_without_overwriting(self):
        archive = self.path("a.tar.gz")
        archive.write_bytes(b"A")
        sig = self.path("a.tar.gz.sigstore.json")
        sig.write_bytes(b"S")
        out = self.path("out")
        M.fetch(archive, sig, out)
        self.assertEqual((out / "a.tar.gz").read_bytes(), b"A")
        self.assertEqual((out / "a.tar.gz.sigstore.json").read_bytes(), b"S")
        self.assertEqual(stat.S_IMODE((out / "a.tar.gz").stat().st_mode), 0o644)
        self.assertFalse(any(p.is_dir() for p in out.iterdir()))
        with self.assertRaises(M.Failure):
            M.fetch(archive, sig, out)


class InstallOrdering(unittest.TestCase):
    def args(self, component):
        return types.SimpleNamespace(component=component, bind="127.0.0.1:8080",
                                     runtime_mode="auto", nats_url="nats://n:4222")

    def test_hub_probes_bind_before_writing_any_file(self):
        probed = []
        with mock.patch.object(M, "system_preflight", mock.MagicMock()), \
                mock.patch.object(M, "installation_lock", return_value=contextlib.nullcontext()), \
                mock.patch.object(M, "fresh_install", mock.MagicMock()), \
                mock.patch.object(M, "check_bind_available",
                                  side_effect=lambda bind: probed.append(bind)), \
                mock.patch.object(M, "credentials_and_connections",
                                  side_effect=M.Failure("stop-before-write")):
            with self.assertRaises(M.Failure):
                M.install(self.args("hub"), Path("/nonexistent"), Path("/tmp"))
        self.assertEqual(probed, ["127.0.0.1:8080"])

    def test_scout_does_not_probe_bind(self):
        probed = []
        with mock.patch.object(M, "system_preflight", mock.MagicMock()), \
                mock.patch.object(M, "installation_lock", return_value=contextlib.nullcontext()), \
                mock.patch.object(M, "fresh_install", mock.MagicMock()), \
                mock.patch.object(M, "doctor", mock.MagicMock()), \
                mock.patch.object(M, "check_bind_available",
                                  side_effect=lambda bind: probed.append(bind)), \
                mock.patch.object(M, "credentials_and_connections",
                                  side_effect=M.Failure("stop-before-write")):
            with self.assertRaises(M.Failure):
                M.install(self.args("scout"), Path("/nonexistent"), Path("/tmp"))
        self.assertEqual(probed, [])


class MainFlow(TempDirMixin, unittest.TestCase):
    def test_verify_only_inspects_but_never_extracts_or_installs(self):
        with linux_amd64(), \
                mock.patch.object(M, "acquire", return_value=(self.path("a.tar.gz"), None)), \
                mock.patch.object(M, "inspect_archive", mock.MagicMock()) as inspect, \
                mock.patch.object(M, "extract_archive", mock.MagicMock()) as extract, \
                mock.patch.object(M, "install", mock.MagicMock()) as install:
            M.main(["--component", "scout", "--version", "v1.0.0", "--verify-only"])
        inspect.assert_called_once()
        extract.assert_not_called()
        install.assert_not_called()

    def test_dry_run_plans_but_never_extracts_or_installs(self):
        with linux_amd64(), \
                mock.patch.object(M, "acquire", return_value=(self.path("a.tar.gz"), None)), \
                mock.patch.object(M, "inspect_archive", mock.MagicMock()), \
                mock.patch.object(M, "extract_archive", mock.MagicMock()) as extract, \
                mock.patch.object(M, "install", mock.MagicMock()) as install, \
                mock.patch.object(M, "plan", mock.MagicMock()) as plan:
            M.main(["--component", "hub", "--version", "v1.0.0", "--dry-run"])
        plan.assert_called_once()
        extract.assert_not_called()
        install.assert_not_called()

    def test_verify_failure_never_reaches_extract_or_install(self):
        labels = []

        def fake_run(argv, label, *, env=None, timeout=90, check=True):
            labels.append(label)
            if label == "原生归档签名验证":
                raise M.Failure("verify failed")
            return result()

        def fake_download(url, target, limit):
            target.write_bytes(b"x")

        with linux_amd64(), \
                mock.patch.object(M, "run", fake_run), \
                mock.patch.object(M, "download", fake_download), \
                mock.patch.object(M, "inspect_archive", mock.MagicMock()) as inspect, \
                mock.patch.object(M, "extract_archive", mock.MagicMock()) as extract, \
                mock.patch.object(M, "install", mock.MagicMock()) as install:
            with self.assertRaises(M.Failure):
                M.main(["--component", "scout", "--version", "v1.0.0", "--verify-only"])
        self.assertIn("原生归档签名验证", labels)
        inspect.assert_not_called()
        extract.assert_not_called()
        install.assert_not_called()

    def test_inspect_failure_never_reaches_extract_or_install(self):
        with linux_amd64(), \
                mock.patch.object(M, "acquire", return_value=(self.path("a.tar.gz"), None)), \
                mock.patch.object(M, "inspect_archive", side_effect=M.Failure("layout")), \
                mock.patch.object(M, "extract_archive", mock.MagicMock()) as extract, \
                mock.patch.object(M, "install", mock.MagicMock()) as install:
            with self.assertRaises(M.Failure):
                M.main(["--component", "hub", "--version", "v1.0.0", "--verify-only"])
        extract.assert_not_called()
        install.assert_not_called()

    def test_install_mode_fails_preflight_before_downloading(self):
        with linux_amd64(), \
                mock.patch.object(M, "system_preflight", side_effect=M.Failure("unsuitable")), \
                mock.patch.object(M, "fresh_install", mock.MagicMock()), \
                mock.patch.object(M, "acquire", mock.MagicMock()) as acquire:
            with self.assertRaises(M.Failure):
                M.main(["--component", "scout", "--version", "v1.0.0",
                        "--nats-url", "nats://n:4222", "--hub-url", "https://hub.example",
                        "--enroll-token-file", "/tmp/e"])
        acquire.assert_not_called()

    def test_fetch_only_links_downloads_without_extracting(self):
        archive = self.path("sentinel-v1.0.0-linux-amd64.tar.gz")
        archive.write_bytes(b"archive")
        sig = self.path("sentinel-v1.0.0-linux-amd64.tar.gz.sigstore.json")
        sig.write_bytes(b"sig")
        out = self.path("out")
        with linux_amd64(), \
                mock.patch.object(M, "acquire", return_value=(archive, sig)), \
                mock.patch.object(M, "inspect_archive", mock.MagicMock()), \
                mock.patch.object(M, "fetch", mock.MagicMock()) as fetch, \
                mock.patch.object(M, "extract_archive", mock.MagicMock()) as extract, \
                mock.patch.object(M, "install", mock.MagicMock()) as install:
            M.main(["--component", "hub", "--version", "v1.0.0",
                    "--fetch-only", "--output-dir", str(out)])
        fetch.assert_called_once_with(archive, sig, out)
        extract.assert_not_called()
        install.assert_not_called()

    def test_plan_mode_does_nothing_else(self):
        with linux_amd64(), \
                mock.patch.object(M, "plan", mock.MagicMock()) as plan, \
                mock.patch.object(M, "acquire", mock.MagicMock()) as acquire:
            M.main(["--component", "hub", "--version", "v1.0.0", "--plan"])
        plan.assert_called_once()
        acquire.assert_not_called()


class InstallFlow(TempDirMixin, unittest.TestCase):
    """install() end-to-end cleanup/state guarantees. Every root and service
    boundary is mocked; only a temp bundle and temp target paths are real."""

    def args(self, component, **over):
        base = dict(component=component, bind="127.0.0.1:8080", runtime_mode="auto",
                    nats_url="nats://n:4222", nats_token_file=None, interval=30,
                    hub_url="https://hub.example", asset_name=None, group_id=None,
                    local_bundle=None)
        base.update(over)
        return types.SimpleNamespace(**base)

    def target_paths(self, component):
        for parent in ("opt", "etc", "var"):
            self.path(parent).mkdir(parents=True, exist_ok=True)
        return {"install": self.path("opt/" + component),
                "config": self.path("etc/" + component),
                "state": self.path("var/" + component),
                "unit": self.path("etc/sentinel-" + component + ".service")}

    def bundle(self, component):
        root = self.path("bundle")
        (root / "bin").mkdir(parents=True, exist_ok=True)
        (root / "deploy/systemd").mkdir(parents=True, exist_ok=True)
        (root / "VERSION").write_bytes(b"v1.0.0\n")
        (root / "ARCH").write_bytes(b"amd64\n")
        (root / "bin" / component).write_bytes(elf_header(62))
        (root / "deploy/systemd" / ("sentinel-" + component + ".service")).write_bytes(b"[Unit]\n")
        if component == "hub":
            (root / "web/dist").mkdir(parents=True, exist_ok=True)
            (root / "web/dist/index.html").write_bytes(b"<!doctype html>")
        return root

    def make_run(self, calls, fail_labels=()):
        def fake(argv, label, *, env=None, timeout=90, check=True):
            calls.append((label, [str(a) for a in argv]))
            if label in fail_labels:
                raise M.Failure(label + "失败")
            return result(0)
        return fake

    def patch_install(self, component, calls, fail_labels=(), wait_failure=False):
        paths = self.target_paths(component)
        token = b"t" * 40
        credentials = ({"nats_token": b"n" * 40, "enroll_token": token}
                       if component == "scout" else
                       {"nats_token": b"n" * 40,
                        "database_url": b"postgres://u@pg:5432/sentinel",
                        "admin_token": b"a" * 40})
        healthy = mock.MagicMock(side_effect=M.Failure("not ready")) if wait_failure \
            else mock.MagicMock()
        stack = contextlib.ExitStack()
        stack.enter_context(mock.patch.object(M, "system_preflight", mock.MagicMock()))
        stack.enter_context(mock.patch.object(M, "installation_lock",
                                              return_value=contextlib.nullcontext()))
        stack.enter_context(mock.patch.object(M, "fresh_install", mock.MagicMock()))
        stack.enter_context(mock.patch.object(M, "trusted_parent", mock.MagicMock()))
        stack.enter_context(mock.patch.object(M, "check_bind_available", mock.MagicMock()))
        stack.enter_context(mock.patch.object(M, "doctor", mock.MagicMock()))
        stack.enter_context(mock.patch.object(M, "run", self.make_run(calls, fail_labels)))
        stack.enter_context(mock.patch.object(M.os, "chown", mock.MagicMock()))
        stack.enter_context(mock.patch.object(M.os, "fchown", mock.MagicMock()))
        stack.enter_context(mock.patch.object(M, "paths_for", return_value=paths))
        stack.enter_context(mock.patch.object(
            M.pwd, "getpwnam", return_value=types.SimpleNamespace(pw_uid=1234, pw_gid=1234)))
        stack.enter_context(mock.patch.object(M, "credentials_and_connections",
                                              return_value=dict(credentials)))
        stack.enter_context(mock.patch.object(M, "wait_healthy", healthy))
        return stack, paths, token

    def labels(self, calls):
        return [label for label, _ in calls]

    def test_scout_enroll_failure_clears_temp_token_and_never_enables(self):
        calls = []
        stack, _, token = self.patch_install("scout", calls, fail_labels=("登记 Scout",))
        temporary = self.path("temporary")
        temporary.mkdir()
        with stack:
            with self.assertRaises(M.Failure):
                M.install(self.args("scout"), self.bundle("scout"), temporary)
        self.assertFalse((temporary / "enrollment-token").exists())
        self.assertNotIn(token.decode(), "".join(
            p.read_text(errors="ignore") for p in self.path("etc/scout").iterdir()
            if p.is_file()))
        self.assertIn("初始化 Scout 身份", self.labels(calls))
        self.assertNotIn("启用并启动服务", self.labels(calls))
        self.assertNotIn("停止本次安装的服务", self.labels(calls))

    def test_ready_failure_disables_only_this_unit_and_keeps_state(self):
        calls = []
        stack, paths, _ = self.patch_install("scout", calls, wait_failure=True)
        temporary = self.path("temporary2")
        temporary.mkdir()
        with stack:
            with self.assertRaises(M.Failure):
                M.install(self.args("scout"), self.bundle("scout"), temporary)
        labels = self.labels(calls)
        self.assertIn("启用并启动服务", labels)
        self.assertIn("停止本次安装的服务", labels)
        disable = [argv for label, argv in calls if label == "停止本次安装的服务"][0]
        self.assertEqual(disable, ["systemctl", "disable", "--now", "sentinel-scout.service"])
        self.assertTrue(paths["state"].is_dir())
        self.assertTrue(paths["unit"].is_file())

    def test_scout_success_resident_config_has_no_admin_token(self):
        calls = []
        stack, paths, token = self.patch_install("scout", calls)
        temporary = self.path("temporary3")
        temporary.mkdir()
        with stack:
            M.install(self.args("scout"), self.bundle("scout"), temporary)
        env_text = (paths["config"] / "scout.env").read_text()
        self.assertNotIn("ADMIN_TOKEN", env_text)
        self.assertNotIn("ENROLL_TOKEN", env_text)
        self.assertNotIn(token.decode(), env_text)
        names = sorted(p.name for p in paths["config"].iterdir())
        self.assertIn("scout.env", names)
        self.assertNotIn("admin-token", names)
        self.assertNotIn("enroll-token", names)
        self.assertTrue(paths["state"].is_dir())
        labels = self.labels(calls)
        self.assertIn("启用并启动服务", labels)
        self.assertNotIn("停止本次安装的服务", labels)

    def test_hub_migrate_failure_never_enables(self):
        calls = []
        stack, _, _ = self.patch_install(
            "hub", calls, fail_labels=("以 Hub 专用账号执行数据库迁移",))
        with stack:
            with self.assertRaises(M.Failure):
                M.install(self.args("hub"), self.bundle("hub"), self.path("temporary4"))
        labels = self.labels(calls)
        self.assertIn("创建 Hub 专用账号", labels)
        self.assertIn("以 Hub 专用账号执行数据库迁移", labels)
        self.assertNotIn("启用并启动服务", labels)
        self.assertNotIn("停止本次安装的服务", labels)


if __name__ == "__main__":
    suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])
    outcome = unittest.TextTestRunner(verbosity=2).run(suite)
    failed = len(outcome.failures) + len(outcome.errors)
    print("\n通过 %d，失败 %d，跳过 %d，预期失败 %d" % (
        outcome.testsRun - failed - len(outcome.skipped) - len(outcome.expectedFailures),
        failed, len(outcome.skipped), len(outcome.expectedFailures)))
    sys.exit(0 if outcome.wasSuccessful() else 1)
