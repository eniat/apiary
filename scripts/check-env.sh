#!/usr/bin/env bash
set -uo pipefail
fails=0
ok(){ printf '  ok   %s\n' "$1"; }
bad(){ printf '  MISS %s\n' "$1"; fails=$((fails + 1)); }
echo "kernel: $(uname -r)"
[[ -f /sys/kernel/btf/vmlinux ]] && ok "btf present" || bad "btf missing (co-re unavailable)"
if command -v clang >/dev/null; then ok "$(clang --version | head -1)"; else bad "clang"; fi
command -v docker  >/dev/null && ok "docker"  || bad "docker"
command -v bpftool >/dev/null && ok "bpftool" || bad "bpftool"
command -v jq      >/dev/null && ok "jq"      || bad "jq"
docker info >/dev/null 2>&1 && ok "docker daemon reachable" || bad "docker daemon"
mount | grep -q cgroup2 && ok "cgroup v2" || bad "cgroup v2"
exit $((fails > 0))
