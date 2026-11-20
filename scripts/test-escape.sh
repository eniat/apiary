#!/usr/bin/env bash
# each attempt should be contained, a BREACH line is a real finding
# the image has no shell utilities so every probe goes through python
set -uo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }

HP="${HP:-$(docker ps --format '{{.Names}}' --filter name=ap-hp- | head -1)}"
docker inspect "$HP" >/dev/null 2>&1 || { echo "no honeypot to test from"; exit 1; }

echo "# escape battery, $(date -u +%Y-%m-%dT%H:%M:%SZ), from $HP"
echo
echo "## attempts from inside"

docker exec -i "$HP" python3 - <<'PY'
import os, socket, ctypes

def row(name, contained, detail=""):
    print("%-26s %-9s %s" % (name, "contained" if contained else "BREACH", detail))

row("docker socket", not os.path.exists("/var/run/docker.sock"), "absent")

eff = ""
for line in open("/proc/self/status"):
    if line.startswith("CapEff:"):
        eff = line.split()[1]
row("effective capabilities", eff == "0" * 16, eff)

try:
    open("/tmp/escape-probe", "w")
    row("write rootfs", False)
except OSError as e:
    row("write rootfs", True, type(e).__name__)

row("bpf redirect pin", not os.path.exists("/sys/fs/bpf/apiary-redirect"), "not visible")

try:
    socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    row("raw packet socket", False)
except Exception as e:
    row("raw packet socket", True, type(e).__name__)

libc = ctypes.CDLL(None, use_errno=True)

buf = ctypes.create_string_buffer(64)
r = libc.syscall(100, buf)
row("seccomp blocks times", r == -1, "errno %d" % ctypes.get_errno())

r = libc.mount(b"proc", b"/mnt", b"proc", 0, None)
row("mount inside", r == -1, "errno %d" % ctypes.get_errno())

s = socket.socket(); s.settimeout(3)
try:
    s.connect(("172.30.0.1", 2375))
    row("docker api on gateway", False)
except Exception as e:
    row("docker api on gateway", True, type(e).__name__)
s.close()
PY

echo
echo "## host side"
echo "uid the honeypot runs as:"
docker inspect -f '  {{.Config.User}}' "$HP"
echo "containers outside the lab naming scheme:"
docker ps --format '{{.Names}}' | grep -v '^ap-\|^mon-' || echo "  none"
