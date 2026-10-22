"""Fictional Ubuntu host view for process-level integration tests.

Never reads the machine running the tests. Counter changes are explicit, so tests
can distinguish the first sample, a valid rate, and a reset without real traffic.
"""

from pathlib import Path


def write_host(root: Path, *, version: str = "24.04", sample: int = 0) -> None:
    root.mkdir(parents=True, exist_ok=True)
    files = {
        "etc/os-release": (
            f'ID=ubuntu\nVERSION_ID="{version}"\nNAME="Ubuntu"\n'
            f'PRETTY_NAME="Ubuntu {version} LTS (fictional test host)"\n'
        ),
        "etc/hostname": "sentinel-fixture-01\n",
        "etc/machine-id": "0123456789abcdef0123456789abcdef\n",
        "var/lib/dpkg/arch": "amd64\n",
        "sys/class/net/eth0/ifindex": "2\n",
        "sys/class/net/eth0/type": "1\n",
        "sys/class/net/lo/ifindex": "1\n",
        "sys/class/net/lo/type": "772\n",
        "proc/sys/kernel/hostname": "sentinel-fixture-01\n",
        "proc/sys/kernel/osrelease": "6.8.0-sentinel-fixture\n",
        "proc/sys/kernel/random/boot_id": "11111111-2222-4333-8444-555555555555\n",
        "proc/cpuinfo": (
            "processor\t: 0\nmodel name\t: Fictional CPU\n\n"
            "processor\t: 1\nmodel name\t: Fictional CPU\n\n"
        ),
        "proc/meminfo": (
            "MemTotal:       8388608 kB\nMemFree:        2097152 kB\n"
            "MemAvailable:  4194304 kB\nBuffers:          65536 kB\n"
            "Cached:        1048576 kB\nSwapTotal:     1048576 kB\n"
            "SwapFree:      1048576 kB\n"
        ),
        "proc/loadavg": "0.50 0.25 0.10 1/100 200\n",
        "proc/uptime": f"{10000 + sample * 30}.00 18000.00\n",
        "proc/stat": (
            f"cpu  {100 + sample * 10} 0 50 {850 + sample * 90} 0 0 0 0 0 0\n"
            f"cpu0 {50 + sample * 5} 0 25 {425 + sample * 45} 0 0 0 0 0 0\n"
            f"cpu1 {50 + sample * 5} 0 25 {425 + sample * 45} 0 0 0 0 0 0\n"
            "btime 1700000000\nprocesses 40000\nprocs_running 1\nprocs_blocked 0\n"
        ),
        "proc/net/dev": (
            "Inter-|   Receive                                                |  Transmit\n"
            " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
            f"  eth0: {100000 + sample * 30000} 100 0 0 0 0 0 0 {50000 + sample * 15000} 50 0 0 0 0 0 0\n"
            "    lo: 500 5 0 0 0 0 0 0 500 5 0 0 0 0 0 0\n"
        ),
        "var/lib/dpkg/status": (
            "Package: fixture-openssl\nStatus: install ok installed\n"
            "Architecture: amd64\nVersion: 3:3.0.13-0ubuntu3.4\n"
            "Source: fixture-openssl-source (3:3.0.13-0ubuntu3.4)\n"
            "Description: fictional package, not an actual vulnerability claim\n\n"
            "Package: fixture-lib\nStatus: install ok installed\n"
            "Architecture: all\nVersion: 1.0-2ubuntu1\n"
            "Description: a second fictional installed package\n\n"
            "Package: fixture-removed\nStatus: deinstall ok config-files\n"
            "Architecture: amd64\nVersion: 0.1-1\n\n"
        ),
    }
    header = (
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
    )
    files["proc/net/tcp"] = header + (
        "   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1001\n"
        "   1: 0200007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1002\n"
        "   2: 0100000A:C001 0200000A:01BB 01 00000000:00000000 00:00000000 00000000 0 0 1003\n"
    )
    files["proc/net/tcp6"] = header + (
        "   0: 00000000000000000000000001000000:1538 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1004\n"
    )
    files["proc/net/udp"] = header + (
        "   0: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000 0 0 1005\n"
    )
    files["proc/net/udp6"] = header
    # Scout explicitly uses host PID 1's network namespace, never the reader's.
    for name in ("dev", "tcp", "tcp6", "udp", "udp6"):
        files[f"proc/1/net/{name}"] = files[f"proc/net/{name}"]
    for pid, name, state in [(1, "fixture-init", "S"), (200, "fixture-worker", "R")]:
        # Values after state begin at proc field 4; starttime is field 22.
        numeric = ["0"] * 49
        numeric[18] = str(pid * 100)
        numeric[19] = "4096000"
        numeric[20] = "100"
        files[f"proc/{pid}/stat"] = f"{pid} ({name}) {state} {' '.join(numeric)}\n"
        files[f"proc/{pid}/comm"] = f"{name}\n"
        files[f"proc/{pid}/status"] = (
            f"Name:\t{name}\nState:\t{state}\nPid:\t{pid}\nThreads:\t1\n"
        )
    for relative, content in files.items():
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding="utf-8")
