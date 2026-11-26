#!/usr/bin/env bash
# each cgroup limit should hold when a honeypot exhausts it from inside
# caps of 512 forks and 1 GiB stop a missing limit from taking the host down
set -uo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }

HP="${HP:-$(docker ps --format '{{.Names}}' --filter name=ap-hp- | head -1)}"
docker inspect "$HP" >/dev/null 2>&1 || { echo "no honeypot to test from"; exit 1; }
IP=$(docker inspect -f '{{(index .NetworkSettings.Networks "apiary-net").IPAddress}}' "$HP")

echo "# limits battery, $(date -u +%Y-%m-%dT%H:%M:%SZ), from $HP"
echo
echo "## attempts from inside"

docker exec -i "$HP" python3 - <<'PY'
import errno, os, signal, time

CG = "/sys/fs/cgroup/"

def row(name, state, detail):
    word = {True: "contained", False: "BREACH", None: "unknown"}[state]
    print("%-26s %-9s %s" % (name, word, detail), flush=True)

def read(name):
    try:
        return open(CG + name).read().strip()
    except OSError as e:
        return "unreadable " + type(e).__name__

def field(name, key):
    for line in read(name).splitlines():
        k, _, v = line.partition(" ")
        if k == key:
            return int(v)
    return -1

u0, t0, w0 = field("cpu.stat", "usage_usec"), field("cpu.stat", "nr_throttled"), time.monotonic()
kids = []
for _ in range(4):
    p = os.fork()
    if p == 0:
        end = time.monotonic() + 5
        while time.monotonic() < end:
            pass
        os._exit(0)
    kids.append(p)
for p in kids:
    os.waitpid(p, 0)
u1, t1, w1 = field("cpu.stat", "usage_usec"), field("cpu.stat", "nr_throttled"), time.monotonic()
if u0 < 0:
    row("cpu limit", None, "cpu.stat " + read("cpu.stat"))
else:
    cores = (u1 - u0) / 1e6 / (w1 - w0)
    row("cpu limit", cores <= 0.55, "4 busy for 5 s used %.2f cpu, throttled %d periods, cpu.max %s" % (cores, t1 - t0, read("cpu.max")))

o0 = field("memory.events", "oom_kill")
r, w = os.pipe()
p = os.fork()
if p == 0:
    os.close(r)
    hold = []
    for mib in range(16, 1025, 16):
        hold.append(b"\x01" * (16 << 20))
        os.write(w, b"%d\n" % mib)
    os._exit(0)
os.close(w)
got = 0
with os.fdopen(r) as f:
    for line in f:
        got = int(line)
_, status = os.waitpid(p, 0)
o1 = field("memory.events", "oom_kill")
killed = os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL
row("memory limit", killed and got < 1024, "reached %d MiB then %s, oom_kill +%d, memory.max %s" % (got, "killed" if killed else "exited", o1 - o0, read("memory.max")))

m0 = field("pids.events", "max")
kids, err = [], 0
try:
    while len(kids) < 512:
        p = os.fork()
        if p == 0:
            time.sleep(30)
            os._exit(0)
        kids.append(p)
except OSError as e:
    err = e.errno
for p in kids:
    os.kill(p, signal.SIGKILL)
for p in kids:
    os.waitpid(p, 0)
m1 = field("pids.events", "max")
row("pids limit", err == errno.EAGAIN, "refused after %d forks errno %d, pids.events max +%d, pids.max %s" % (len(kids), err, m1 - m0, read("pids.max")))
PY

echo
echo "## host side"
echo "honeypot still answering:"
timeout 5 bash -c "exec 3<>/dev/tcp/$IP/2222" && echo "  yes" || echo "  no"
echo "load average:"
echo "  $(cut -d' ' -f1-3 /proc/loadavg)"
