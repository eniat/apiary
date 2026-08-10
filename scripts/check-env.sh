#!/usr/bin/env bash
set -uo pipefail
fails=0
sudo -v
ok(){ printf '  ok   %s\n' "$1"; }
bad(){ printf '  MISS %s\n' "$1"; fails=$((fails + 1)); }
echo "kernel: $(uname -r)"
[[ -f /sys/kernel/btf/vmlinux ]] && ok "btf present" || bad "btf missing (co-re unavailable)"
if command -v clang >/dev/null; then ok "$(clang --version | head -1)"; else bad "clang"; fi
command -v docker >/dev/null && ok "docker" || bad "docker"
command -v bpftool >/dev/null && ok "bpftool" || bad "bpftool"
command -v jq >/dev/null && ok "jq" || bad "jq"
docker info >/dev/null 2>&1 && ok "docker daemon reachable" || bad "docker daemon"
mount | grep -q cgroup2 && ok "cgroup v2" || bad "cgroup v2"
{ sudo test -e /sys/kernel/debug/tracing/trace_pipe || sudo test -e /sys/kernel/tracing/trace_pipe; } && ok "trace_pipe" || bad "trace_pipe, mount debugfs"
probe=$(sudo bpftool feature probe kernel 2>/dev/null)
case "$probe" in *sched_cls*) ok "tc program type";; *) bad "tc program type, data plane unbuildable";; esac
if sudo tc qdisc add dev lo clsact 2>/dev/null; then sudo tc qdisc del dev lo clsact 2>/dev/null; ok "clsact hook"; else bad "clsact hook, data plane unbuildable"; fi
sudo aa-status >/dev/null 2>&1 && ok "apparmor" || bad "apparmor"
exit $((fails > 0))
