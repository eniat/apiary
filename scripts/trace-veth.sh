#!/usr/bin/env bash
# container's eth0 iflink holds the hostside ifindex of veth peer
# that host end is the attach point for the data plane
set -euo pipefail
container="${1:?usage: trace-veth.sh <container> [count]}"
count="${2:-20}"

iflink=$(docker exec "$container" python3 -c \
  "print(open('/sys/class/net/eth0/iflink').read().strip())" | tr -d '\r')

veth=$(ip -o link | awk -F': ' -v i="$iflink" '$1 == i {print $2}' | cut -d'@' -f1)
[[ -n "$veth" ]] || { echo "no host interface with ifindex $iflink"; exit 1; }

master=$(ip -o link show "$veth" | grep -o 'master [^ ]*' || echo "master none")
echo "$container -> $veth (ifindex $iflink, $master)"
sudo tcpdump -ni "$veth" -c "$count"
