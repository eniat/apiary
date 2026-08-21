#!/usr/bin/env bash
# builds two netns a veth each both ends plugged into a bridge
# 10.200.0.0/24 so it cant collide with the lab
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }

cleanup() {
  ip netns del ap-demo1 2>/dev/null || true
  ip netns del ap-demo2 2>/dev/null || true
  ip link del br-demo 2>/dev/null || true
}
trap cleanup EXIT
cleanup

ip link add br-demo type bridge
ip addr add 10.200.0.1/24 dev br-demo
ip link set br-demo up

for n in 1 2; do
  ip netns add "ap-demo$n"
  ip link add "veth-h$n" type veth peer name "veth-n$n"
  ip link set "veth-n$n" netns "ap-demo$n"
  ip netns exec "ap-demo$n" ip addr add "10.200.0.$((n + 1))/24" dev "veth-n$n"
  ip netns exec "ap-demo$n" ip link set "veth-n$n" up
  ip netns exec "ap-demo$n" ip link set lo up
  ip link set "veth-h$n" master br-demo
  ip link set "veth-h$n" up
done

echo "== ns1 to ns2, through the bridge"
ip netns exec ap-demo1 ping -c 2 10.200.0.3
echo
echo "== learned macs"
bridge fdb show br br-demo | grep -v permanent
