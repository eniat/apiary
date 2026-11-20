#!/usr/bin/env bash
set -euo pipefail

LAB_NET="${LAB_NET:-10.10.10.0/24}"
HP_NET="${HP_NET:-172.30.0.0/16}"

# insert, for rules that must sit above docker's own
add() {
  local table=$1; shift
  sudo iptables -t "$table" -C "$@" 2>/dev/null || sudo iptables -t "$table" -I "$@"
}

# append, for the egress rules which must sit below the accepts
app() {
  local table=$1; shift
  sudo iptables -t "$table" -C "$@" 2>/dev/null || sudo iptables -t "$table" -A "$@"
}

# the honeypot profile lives in the repo so it is not loaded at boot
root="$(cd "$(dirname "$0")/.." && pwd)"
sudo apparmor_parser -r -W "$root/honeypots/cowrie/apparmor.profile"

add raw PREROUTING -s "$LAB_NET" -d "$HP_NET" -j ACCEPT
add filter DOCKER-USER -s "$LAB_NET" -d "$HP_NET" -j ACCEPT

# a honeypot answers connections and never starts one
# established first or the readiness dial loses its replies
app filter DOCKER-USER -s "$HP_NET" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
app filter DOCKER-USER -s "$HP_NET" -j DROP

# reaching the host is not forwarded so DOCKER-USER never sees it
app filter INPUT -s "$HP_NET" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
app filter INPUT -s "$HP_NET" -j DROP

echo "lab rules applied"
