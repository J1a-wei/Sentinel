#!/usr/bin/env bash
# Standalone native installer. Python is embedded so downloading this file is sufficient.
# No shell evaluation of configuration; credentials remain in private files.
set -euo pipefail
exec python3 - "$@" <<'PY'
import argparse
import contextlib
import fcntl
import grp
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import platform
import pwd
import re
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

REPOSITORY = "https://github.com/J1a-wei/Sentinel"
IDENTITY = REPOSITORY + "/.github/workflows/release.yml"
ISSUER = "https://token.actions.githubusercontent.com"
ARCHES = {"x86_64": ("amd64", 62), "aarch64": ("arm64", 183)}
MAX_ARCHIVE = 512 * 1024 * 1024
MAX_CONTENT = 1024 * 1024 * 1024
BASE_ENV = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"}


class Failure(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Failure(message)


def run(argv, label, *, env=None, timeout=90, check=True):
    # Do not echo child output: it can contain connection strings or host data.
    try:
        result = subprocess.run([str(arg) for arg in argv], env=BASE_ENV | (env or {}),
                                capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        raise Failure(label + "失败（程序不可用或超时）") from None
    if check:
        require(result.returncode == 0, label + "失败；未输出可能包含凭证的子进程日志")
    return result


def safe_text(value):
    require(not any(ord(c) < 32 or ord(c) == 127 for c in value), "参数不能含控制字符")
    return value


def environment_text(values):
    lines = []
    for key, value in values.items():
        require(re.fullmatch(r"[A-Z][A-Z0-9_]*", key), "环境变量名无效")
        value = safe_text(str(value)).replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'{key}="{value}"\n')
    return "".join(lines)


def endpoint(value, schemes):
    safe_text(value)
    require(not any(c.isspace() for c in value) and "\\" not in value, "连接地址格式无效")
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
        valid = (parsed.scheme in schemes and parsed.hostname and parsed.username is None
                 and parsed.password is None and not parsed.query and not parsed.fragment
                 and parsed.path in ("", "/") and port != 0)
        require(valid, "连接地址必须包含主机，不允许 userinfo、查询参数或路径；凭证请使用文件")
    except ValueError:
        raise Failure("连接地址格式无效") from None
    return parsed


def validate_bind(value):
    try:
        host, port = value.rsplit(":", 1)
        ipaddress.ip_address(host.strip("[]"))
        require(1 <= int(port) <= 65535, "--bind 端口无效")
        if ":" in host:
            require(host.startswith("[") and host.endswith("]"), "IPv6 bind 必须使用方括号")
    except ValueError:
        raise Failure("--bind 必须是 IP:端口（IPv6 使用 [IP]:端口）") from None


def check_bind_available(value):
    host, port = value.rsplit(":", 1)
    host = host[1:-1] if host.startswith("[") else host
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as listener:
            # Do not enable SO_REUSEADDR/SO_REUSEPORT for this exclusive probe.
            listener.bind((host, int(port)))
    except OSError:
        raise Failure("Hub 监听地址已占用或不可绑定；请调整 --bind，不会停止已有服务") from None


def arguments(argv=None):
    parser = argparse.ArgumentParser(description="Sentinel 原生 Hub/Scout systemd 安装器；仅全新安装，不覆盖或升级")
    parser.add_argument("--component", choices=("hub", "scout"), required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--local-bundle", type=Path, help="显式信任本地未签名开发包")
    parser.add_argument("--hub-url")
    parser.add_argument("--nats-url")
    for flag in ("nats-token-file", "enroll-token-file", "database-url-file", "admin-token-file"):
        parser.add_argument("--" + flag, type=Path)
    parser.add_argument("--bind", default="127.0.0.1:8080")
    parser.add_argument("--runtime-mode", choices=("auto", "native"), default="auto")
    parser.add_argument("--interval", type=int, default=30)
    parser.add_argument("--asset-name")
    parser.add_argument("--group-id")
    parser.add_argument("--output-dir", type=Path)
    modes = parser.add_mutually_exclusive_group()
    for flag in ("plan", "dry-run", "verify-only", "fetch-only"):
        modes.add_argument("--" + flag, action="store_true")
    args = parser.parse_args(argv)
    require(re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:[-.][0-9A-Za-z.]+)?", args.version), "版本必须为 vX.Y.Z，可带发布后缀")
    require(platform.system() == "Linux" and platform.machine() in ARCHES, "仅支持 Linux amd64/arm64")
    args.arch, args.machine = ARCHES[platform.machine()]
    args.mode = next((name for name in ("plan", "dry_run", "verify_only", "fetch_only") if getattr(args, name)), "install")
    require(5 <= args.interval <= 3600, "--interval 必须在 5..3600 秒之间")
    validate_bind(args.bind)
    if args.hub_url:
        endpoint(args.hub_url, ("http", "https"))
    if args.nats_url:
        endpoint(args.nats_url, ("nats", "tls"))
    if args.asset_name:
        require(re.fullmatch(r"[A-Za-z0-9._-]{1,64}", args.asset_name), "资产名仅允许字母、数字、点、下划线、横线，最长 64 字符")
    if args.group_id:
        try:
            uuid.UUID(args.group_id)
        except ValueError:
            raise Failure("--group-id 必须是 UUID") from None
    require(not args.fetch_only or args.output_dir is not None, "--fetch-only 需要 --output-dir")
    require(args.output_dir is None or args.fetch_only, "--output-dir 仅用于 --fetch-only")
    if args.component == "scout":
        require(not args.database_url_file and not args.admin_token_file, "Scout 登记请用 --enroll-token-file")
    else:
        require(not args.enroll_token_file and not args.asset_name and not args.group_id, "Hub 不接受 Scout 登记参数")
    if args.mode == "install":
        require(args.nats_url, "安装需要 --nats-url")
        if args.component == "hub":
            require(args.database_url_file and args.admin_token_file, "Hub 需要 --database-url-file 和 --admin-token-file")
        else:
            require(args.hub_url and args.enroll_token_file, "Scout 需要 --hub-url 和 --enroll-token-file")
    return args


def copy_limited(source, destination, limit):
    total = 0
    while True:
        chunk = source.read(min(1024 * 1024, limit + 1 - total))
        if not chunk:
            break
        total += len(chunk)
        require(total <= limit, "文件超过大小上限")
        destination.write(chunk)


def private_bytes(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        metadata = os.fstat(source.fileno())
        require(stat.S_ISREG(metadata.st_mode) and not metadata.st_mode & 0o077,
                "凭证必须是无组/其他用户权限的普通文件（建议 chmod 600），不能是链接")
        data = source.read(16385)
    require(0 < len(data) <= 16384, "凭证文件为空或超过 16 KiB")
    require(data.rstrip(b"\r\n") and b"\0" not in data, "凭证文件无效")
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        raise Failure("凭证必须是 UTF-8 文本") from None
    return data


def write_file(path, data, mode=0o600, owner=None):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(descriptor, "wb") as output:
        os.fchmod(output.fileno(), mode)
        if owner:
            os.fchown(output.fileno(), *owner)
        output.write(data if isinstance(data, bytes) else data.encode())


def download(url, target, limit):
    # Only fixed release URLs are constructed by the caller. GitHub redirects
    # attachment downloads to its HTTPS artifact storage.
    with urllib.request.urlopen(url, timeout=60) as response, target.open("xb") as output:
        require(urllib.parse.urlsplit(response.url).scheme == "https", "拒绝非 HTTPS 下载")
        copy_limited(response, output, limit)


def acquire(args, temporary):
    name = f"sentinel-{args.version}-linux-{args.arch}.tar.gz"
    archive = temporary / name
    if args.local_bundle:
        print("本地未签名开发包：未进行发布身份验签；仅使用你信任的自建包。")
        with args.local_bundle.open("rb") as source, archive.open("xb") as output:
            require(stat.S_ISREG(os.fstat(source.fileno()).st_mode), "本地包必须是普通文件")
            copy_limited(source, output, MAX_ARCHIVE)
        return archive, None
    run(["cosign", "version"], "检查 Cosign")
    signature = temporary / (name + ".sigstore.json")
    # Never let an elevated verifier read shared/fallback TUF caches. The clean
    # environment also excludes caller-provided trust-root overrides.
    tuf = temporary / "cosign-tuf"
    tuf.mkdir(mode=0o700)
    tuf.chmod(0o700)
    base = REPOSITORY + "/releases/download/" + args.version + "/"
    download(base + name, archive, MAX_ARCHIVE)
    download(base + signature.name, signature, 8 * 1024 * 1024)
    run(["cosign", "verify-blob", "--bundle", signature,
         "--certificate-identity", IDENTITY + "@refs/tags/" + args.version,
         "--certificate-oidc-issuer", ISSUER, archive], "原生归档签名验证",
        env={"TUF_ROOT": str(tuf)}, timeout=180)
    print("原生归档发布签名已通过（精确工作流、标签及 OIDC issuer）。")
    return archive, signature


def inspect_archive(archive, version, arch, machine):
    required = {"VERSION", "ARCH", "bin/hub", "bin/scout", "web/dist/index.html",
                "deploy/systemd/sentinel-hub.service", "deploy/systemd/sentinel-scout.service"}
    names, total = set(), 0
    with tarfile.open(archive, "r:gz") as bundle:
        for member in bundle:
            name = member.name
            parts = name.split("/")
            require(member.isfile() and not member.issparse() and not member.pax_headers,
                    "归档只允许普通文件，禁止链接、设备和扩展覆盖")
            require(not name.startswith("/") and all(p not in ("", ".", "..") for p in parts)
                    and "\\" not in name and safe_text(name) and name not in names,
                    "归档路径非法或重复")
            require(name in required or (name.startswith("web/dist/") and len(parts) > 2), "归档包含布局外文件")
            require(not any(parent.as_posix() in names for parent in PurePosixPath(name).parents), "归档路径冲突")
            require(not any(old.startswith(name + "/") for old in names), "归档路径冲突")
            names.add(name)
            total += member.size
            require(len(names) <= 10000 and 0 <= member.size <= MAX_CONTENT and total <= MAX_CONTENT, "归档展开超过预算")
            if name in ("VERSION", "ARCH"):
                require(member.size <= 128, "归档元数据过长")
                expected = version if name == "VERSION" else arch
                require(bundle.extractfile(member).read() == (expected + "\n").encode(), "归档版本或架构与请求不符")
            if name in ("bin/hub", "bin/scout"):
                header = bundle.extractfile(member).read(64)
                require(len(header) == 64 and header[:6] == b"\x7fELF\x02\x01"
                        and struct.unpack_from("<H", header, 18)[0] == machine, "归档二进制架构不符")
            if name.startswith("deploy/systemd/"):
                require(0 < member.size < 65536, "归档 systemd 单元为空或过长")
        require(required <= names, "归档缺少必需文件")


def extract_archive(archive, destination):
    # Called only after signature (or explicit local trust) and layout checks.
    # No tar.extractall: create each validated path ourselves without links.
    destination.mkdir(mode=0o700)
    with tarfile.open(archive, "r:gz") as bundle:
        for member in bundle:
            target = destination / member.name
            for parent in reversed(target.relative_to(destination).parents):
                directory = destination / parent
                if not directory.exists():
                    directory.mkdir(mode=0o755)
                    directory.chmod(0o755)
            with bundle.extractfile(member) as source, target.open("xb") as output:
                copy_limited(source, output, member.size)
            target.chmod(0o755 if member.name in ("bin/hub", "bin/scout") else 0o644)


def paths_for(component):
    return {"install": Path("/opt/sentinel") / component,
            "config": Path("/etc/sentinel") / component,
            "state": Path("/var/lib/sentinel-" + component),
            "unit": Path("/etc/systemd/system/sentinel-" + component + ".service")}


def trusted_parent(path, *, accessible=False):
    for item in reversed([path, *path.parents]):
        if not item.exists():
            item.mkdir(mode=0o755)
            item.chmod(0o755)
        meta = item.lstat()
        require(stat.S_ISDIR(meta.st_mode) and meta.st_uid == 0 and not meta.st_mode & 0o022,
                "安装父目录必须由 root 所有且禁止组/其他用户写入，不能是链接")
        require(not accessible or meta.st_mode & 0o001, "Hub 安装父目录需要可遍历权限；请审查已有目录配置")


def fresh_install(component, paths):
    require(not any(os.path.lexists(path) for path in paths.values()), "发现已有安装、配置或状态；拒绝覆盖/升级，请保留身份与队列")
    name = "sentinel-" + component + ".service"
    for directory in ("/etc/systemd/system", "/run/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"):
        require(not os.path.lexists(Path(directory) / name) and not os.path.lexists(Path(directory) / (name + ".d")),
                "发现已有同名服务或覆盖配置；拒绝覆盖")
    loaded = run(["systemctl", "show", name, "--property=LoadState", "--value"], "检查已有服务", check=False)
    require(loaded.stdout.strip() == "not-found", "同名 systemd 服务已加载或无法确认其状态")
    if component == "hub":
        for lookup in (pwd.getpwnam, grp.getgrnam):
            try:
                lookup("sentinel-hub")
            except KeyError:
                continue
            raise Failure("sentinel-hub 用户或组已存在；拒绝复用未知账号")


def system_preflight():
    require(os.geteuid() == 0, "完整安装需要 root；预览和验签不需要 root")
    values = {}
    for line in Path("/etc/os-release").read_text().splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value.strip('"')
    require(values.get("ID") == "ubuntu" and values.get("VERSION_ID") in ("22.04", "24.04"), "仅支持 Ubuntu 22.04/24.04")
    require(Path("/run/systemd/system").is_dir(), "需要 systemd 作为系统服务管理器")
    result = run(["systemd-detect-virt", "--container", "--quiet"], "检测容器环境", check=False)
    require(result.returncode == 1, "容器环境或环境无法确认；请使用容器部署路线")


@contextlib.contextmanager
def installation_lock():
    descriptor = os.open("/run/lock/sentinel-native-install.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        meta = os.fstat(descriptor)
        require(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and not meta.st_mode & 0o077, "安装锁权限无效")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Failure("另一个原生安装进程正在运行") from None
        yield
    finally:
        os.close(descriptor)


def check_connection(host, port, label):
    try:
        with socket.create_connection((host, port), timeout=5):
            pass
    except OSError:
        raise Failure(label + "不可达；本脚本不安装 PostgreSQL 或 NATS") from None


def credentials_and_connections(args):
    credentials = {}
    for key in ("nats_token", "database_url", "admin_token", "enroll_token"):
        source = getattr(args, key + "_file")
        if source:
            credentials[key] = private_bytes(source)
    for key in ("admin_token", "enroll_token"):
        if key in credentials:
            require(len(credentials[key].rstrip(b"\r\n")) >= 32, "管理员/登记令牌至少需要 32 字节")
    parsed = endpoint(args.nats_url, ("nats", "tls"))
    check_connection(parsed.hostname, parsed.port or 4222, "NATS")
    if args.component == "hub":
        try:
            database = urllib.parse.urlsplit(credentials["database_url"].decode().rstrip("\r\n"))
            require(database.scheme in ("postgres", "postgresql") and database.hostname and database.path not in ("", "/"), "数据库文件需要包含带主机和库名的 PostgreSQL URL")
            check_connection(database.hostname, database.port or 5432, "PostgreSQL")
        except ValueError:
            raise Failure("数据库 URL 文件格式无效") from None
    else:
        parsed = endpoint(args.hub_url, ("http", "https"))
        check_connection(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80), "Hub")
    return credentials


def doctor(binary, mode):
    result = run([binary, "doctor"], "Scout 只读宿主诊断", env={"SENTINEL_RUNTIME_MODE": mode}, check=False)
    try:
        report = json.loads(result.stdout)
    except (ValueError, TypeError):
        raise Failure("Scout doctor 未返回有效 JSON") from None
    require(result.returncode == 0 and isinstance(report, dict) and report.get("selected_mode") == "native"
            and report.get("collection_allowed") is True, "Scout 拒绝采集：需要明确的原生宿主；确认宿主后可显式传 --runtime-mode native")


def resident_values(args, paths):
    values = {"SENTINEL_NATS_URL": args.nats_url, "RUST_LOG": "info"}
    if args.nats_token_file:
        values["SENTINEL_NATS_TOKEN_FILE"] = str(paths["config"] / "nats-token")
    if args.component == "hub":
        values.update(SENTINEL_DATABASE_URL_FILE=str(paths["config"] / "database-url"),
                      SENTINEL_ADMIN_TOKEN_FILE=str(paths["config"] / "admin-token"),
                      SENTINEL_WEB_DIR=str(paths["install"] / "web/dist"), SENTINEL_BIND=args.bind)
    else:
        values.update(SENTINEL_RUNTIME_MODE=args.runtime_mode, SENTINEL_STATE_DIR=str(paths["state"]),
                      SENTINEL_NETWORK_PROC_PREFIX="proc/1/net", SENTINEL_INTERVAL_SECONDS=str(args.interval))
    return values


def service_state(service):
    result = run(["systemctl", "show", service, "--property=MainPID", "--property=NRestarts",
                  "--property=ActiveState", "--property=SubState"], "检查本次服务进程", check=False)
    if result.returncode:
        return {}
    return dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)


def hub_session(args, paths):
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    host, port = args.bind.rsplit(":", 1)
    address = ipaddress.ip_address(host.strip("[]"))
    if address.is_unspecified:
        address = ipaddress.ip_address("::1" if address.version == 6 else "127.0.0.1")
    host = f"[{address}]" if address.version == 6 else str(address)
    # A local readiness probe must not send the credential through proxy envs
    # or follow a redirect. The token is read only into this process's memory.
    token = private_bytes(paths["config"] / "admin-token").decode().rstrip("\r\n")
    try:
        request = urllib.request.Request(f"http://{host}:{port}/api/v1/session",
                                         headers={"Authorization": "Bearer " + token})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        with opener.open(request, timeout=4) as response:
            data = response.read(4097)
            if response.status != 200 or len(data) > 4096:
                return False
        session = json.loads(data)
        return (isinstance(session, dict) and session.get("role") == "admin"
                and session.get("authentication") == "administrator_token")
    except (OSError, ValueError, UnicodeError):
        return False


def wait_healthy(args, paths, values):
    service = "sentinel-" + args.component + ".service"
    for _ in range(30):
        active = run(["systemctl", "is-active", "--quiet", service], "检查服务状态", check=False)
        if active.returncode == 0:
            if args.component == "hub":
                before = service_state(service)
                require(before.get("NRestarts", "0") == "0", "本次 Hub 已重启；不能判为首次启动成功")
                running = (before.get("ActiveState") == "active" and before.get("SubState") == "running"
                           and before.get("MainPID", "0").isdigit() and int(before.get("MainPID", "0")) > 0)
                if (running and run([paths["install"] / "bin/hub", "health"], "Hub 就绪检查",
                                    env={"SENTINEL_BIND": args.bind}, check=False).returncode == 0
                        and hub_session(args, paths)):
                    time.sleep(3)
                    after = service_state(service)
                    require(after == before, "Hub 就绪检查期间进程退出或重启；保留状态供排查")
                    if (run([paths["install"] / "bin/hub", "health"], "复核 Hub 就绪",
                            env={"SENTINEL_BIND": args.bind}, check=False).returncode == 0
                            and hub_session(args, paths)):
                        require(service_state(service) == before, "Hub 就绪复核期间进程发生变化")
                        return
            else:
                time.sleep(3)
                status = run([paths["install"] / "bin/scout", "status"], "Scout 只读状态", env=values)
                try:
                    report = json.loads(status.stdout)
                    require(isinstance(report, dict) and report.get("asset_id"), "Scout 尚未登记")
                except ValueError:
                    raise Failure("Scout 状态返回无效") from None
                active = run(["systemctl", "is-active", "--quiet", service], "检查 Scout 运行状态", check=False)
                restarts = run(["systemctl", "show", service, "--property=NRestarts", "--value"], "检查 Scout 重启次数")
                if active.returncode == 0 and restarts.stdout.strip() == "0":
                    return
                raise Failure("Scout 启动后退出或重启；请检查该服务日志")
        time.sleep(2)
    raise Failure("服务未在等待期限内就绪；请检查该服务日志")


def install(args, bundle, temporary):
    system_preflight()
    paths = paths_for(args.component)
    service = "sentinel-" + args.component + ".service"
    with installation_lock():
        fresh_install(args.component, paths)
        if args.component == "scout":
            doctor(bundle / "bin/scout", args.runtime_mode)
        else:
            check_bind_available(args.bind)
        credentials = credentials_and_connections(args)
        # Verify parent ownership before creating a dedicated account or files.
        for key, path in paths.items():
            trusted_parent(path.parent, accessible=args.component == "hub" and key in ("install", "config"))
        owner = (0, 0)
        if args.component == "hub":
            run(["useradd", "--system", "--user-group", "--no-create-home", "--home-dir", str(paths["state"]),
                 "--shell", "/usr/sbin/nologin", "sentinel-hub"], "创建 Hub 专用账号")
            account = pwd.getpwnam("sentinel-hub")
            owner = (account.pw_uid, account.pw_gid)
        paths["install"].mkdir(mode=0o755)
        paths["install"].chmod(0o755)
        (paths["install"] / "bin").mkdir(mode=0o755)
        (paths["install"] / "bin").chmod(0o755)
        for name in ("VERSION", "ARCH", "bin/" + args.component):
            shutil.copyfile(bundle / name, paths["install"] / name)
            (paths["install"] / name).chmod(0o755 if name.startswith("bin/") else 0o644)
        if args.component == "hub":
            shutil.copytree(bundle / "web", paths["install"] / "web")
        paths["config"].mkdir(mode=0o750 if args.component == "hub" else 0o700)
        paths["config"].chmod(0o750 if args.component == "hub" else 0o700)
        os.chown(paths["config"], 0, owner[1])
        paths["state"].mkdir(mode=0o700)
        paths["state"].chmod(0o700)
        os.chown(paths["state"], *owner)
        for key, value in credentials.items():
            if key != "enroll_token":
                write_file(paths["config"] / key.replace("_", "-"), value, owner=owner)
        values = resident_values(args, paths)
        write_file(paths["config"] / (args.component + ".env"), environment_text(values))
        write_file(paths["unit"], (bundle / "deploy/systemd" / service).read_bytes(), 0o644)
        run(["systemd-analyze", "verify", "--man=no", paths["unit"]], "校验正式 systemd 单元")
        if args.component == "hub":
            run(["runuser", "-u", "sentinel-hub", "--", paths["install"] / "bin/hub", "migrate"],
                "以 Hub 专用账号执行数据库迁移", env=values, timeout=180)
        if args.component == "scout":
            executable = paths["install"] / "bin/scout"
            run([executable, "init"], "初始化 Scout 身份", env=values)
            enrollment = temporary / "enrollment-token"
            write_file(enrollment, credentials.pop("enroll_token"))
            enroll_values = values | {"SENTINEL_HUB_URL": args.hub_url, "SENTINEL_ADMIN_TOKEN_FILE": str(enrollment)}
            if args.asset_name:
                enroll_values["SENTINEL_ASSET_NAME"] = args.asset_name
            if args.group_id:
                enroll_values["SENTINEL_GROUP_ID"] = args.group_id
            try:
                run([executable, "enroll"], "登记 Scout", env=enroll_values)
            finally:
                enrollment.unlink(missing_ok=True)
        run(["systemctl", "daemon-reload"], "重新加载服务单元")
        try:
            run(["systemctl", "enable", "--now", service], "启用并启动服务")
            wait_healthy(args, paths, values)
        except BaseException:
            # This unit did not exist before this invocation; never stop others.
            stopped = run(["systemctl", "disable", "--now", service], "停止本次安装的服务", check=False)
            if stopped.returncode:
                print("警告：本次服务停止失败；请人工检查。状态与身份目录已保留。", file=sys.stderr)
            raise
        print(f"{service} 已启动并通过检查。身份/队列保留在 {paths['state']}。")
        if args.component == "scout":
            print("Scout 已登记并常驻；是否收到新数据请在 Hub 资产页确认。")


def plan(args):
    paths = paths_for(args.component)
    print(f"计划：{args.component} {args.version} / Linux {args.arch} / systemd")
    print(f"程序 {paths['install']}；配置 {paths['config']}；持久状态 {paths['state']}")
    print("来源：本地未签名开发包" if args.local_bundle else "来源：GitHub Release；Cosign verify-blob 精确发布身份验签")
    print("步骤：校验归档 → 全新安装检查 → 宿主/依赖预检 → 私有凭证 → 登记或 Hub 启动迁移 → systemd 启动及就绪检查")
    print("不安装数据库、NATS 或 Docker；不覆盖已有安装；不执行自动升级。")


def fetch(archive, signature, output):
    output.mkdir(parents=True, exist_ok=True)
    sources = [archive] + ([signature] if signature else [])
    require(not any(os.path.lexists(output / source.name) for source in sources), "下载目标已存在；拒绝覆盖")
    # Stage complete files on the destination filesystem; link is no-clobber.
    with tempfile.TemporaryDirectory(prefix=".sentinel-download-", dir=output) as tmp:
        for source in sources:
            staged = Path(tmp) / source.name
            shutil.copyfile(source, staged)
            staged.chmod(0o644)
        for source in sources:
            os.link(Path(tmp) / source.name, output / source.name)
    print("归档已保存；未解包、未执行、未安装服务。")


def main(argv=None):
    args = arguments(argv)
    if args.mode == "plan":
        plan(args)
        return
    if args.mode == "install":
        # Fail before network/download when invoked on an unsuitable host.
        system_preflight()
        fresh_install(args.component, paths_for(args.component))
    with tempfile.TemporaryDirectory(prefix="sentinel-native-install-") as name:
        temporary = Path(name)
        archive, signature = acquire(args, temporary)
        inspect_archive(archive, args.version, args.arch, args.machine)
        if args.mode in ("dry_run", "verify_only"):
            print("归档布局、版本和架构校验通过；未解包、未执行、未安装服务。")
            if args.mode == "dry_run":
                plan(args)
            return
        if args.mode == "fetch_only":
            fetch(archive, signature, args.output_dir)
            return
        bundle = temporary / "bundle"
        extract_archive(archive, bundle)
        install(args, bundle, temporary)


if __name__ == "__main__":
    try:
        main()
    except Failure as error:
        print("错误：" + str(error), file=sys.stderr)
        sys.exit(1)
    except (OSError, ValueError, tarfile.TarError):
        # Library errors can include a credential URL or sensitive source text.
        print("错误：文件、网络或归档操作失败；请检查路径、权限和发布附件。已有状态保留。", file=sys.stderr)
        sys.exit(1)
PY
