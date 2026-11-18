#!/usr/bin/env bash
# a connect attempt per destination from inside a honeypot
# the internet rows only mean anything with the nat cable connected
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }

HP="${HP:-$(docker ps --format '{{.Names}}' --filter name=ap-hp- | head -1)}"
[[ -n "$HP" ]] || HP=ap-cowrie
docker inspect "$HP" >/dev/null 2>&1 || { echo "no honeypot to test from"; exit 1; }
DIP="$(docker inspect -f '{{(index .NetworkSettings.Networks "apiary-net").IPAddress}}' ap-dionaea)"

if timeout 3 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443' 2>/dev/null; then
  cable=connected
else
  cable=disconnected
fi

echo "# egress battery, $(date -u +%Y-%m-%dT%H:%M:%SZ), from $HP, nat cable $cable"
echo
echo "## rules before"
iptables -L DOCKER-USER -n -v
iptables -L INPUT -n -v | head -4
echo
echo "## attempts"
docker exec "$HP" python3 -c "
import socket
targets = [
    ('127.0.0.1', 2222, 'own loopback'),
    ('8.8.8.8', 53, 'internet address'),
    ('1.1.1.1', 443, 'internet address'),
    ('example.com', 80, 'internet by name'),
    ('10.0.0.1', 22, 'rfc1918 ten'),
    ('172.16.0.1', 22, 'rfc1918 one seven two'),
    ('192.168.1.1', 80, 'rfc1918 one nine two'),
    ('172.30.0.1', 22, 'bridge gateway'),
    ('10.10.10.10', 22, 'defender lab address'),
    ('10.10.10.1', 445, 'host on the lab segment'),
    ('10.10.10.20', 22, 'attacker'),
    ('$DIP', 445, 'another container'),
]
for host, port, what in targets:
    s = socket.socket(); s.settimeout(3)
    try:
        s.connect((host, port))
        print('%-24s %-22s %s' % (what, '%s:%d' % (host, port), 'OPEN'))
    except Exception as e:
        print('%-24s %-22s %s' % (what, '%s:%d' % (host, port), type(e).__name__))
    s.close()
"
echo
echo "## rules after"
iptables -L DOCKER-USER -n -v
iptables -L INPUT -n -v | head -4
