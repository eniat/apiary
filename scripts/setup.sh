#!/usr/bin/env bash
set -uo pipefail

log()  { printf '\n\033[1;33m==> %s\033[0m\n' "$1"; }
ok()   { printf '  \033[32mok\033[0m   %s\n' "$1"; }
have() { command -v "$1" >/dev/null 2>&1; }

if [[ $EUID -eq 0 ]]; then
  echo "run as a normal user, not root. sudo is used where needed."
  exit 1
fi

log "timezone to UTC"
# Events are correlated on timestamp so clock skew corrupts the graph silently
sudo timedatectl set-timezone UTC
ok "$(timedatectl show -p Timezone --value)"

log "base packages"
sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq

sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
  build-essential pkg-config git curl ca-certificates jq \
  iproute2 iputils-ping tcpdump net-tools \
  python3 python3-venv \
  apparmor-utils shellcheck asciinema

log "ebpf toolchain"
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
  clang llvm libbpf-dev libelf-dev zlib1g-dev \
  "linux-headers-$(uname -r)" \
  linux-tools-common "linux-tools-$(uname -r)" linux-tools-generic

# Arch headers sit under a triplet path on ubuntu amd64 so the asm/types.h include misses them
if [[ -d /usr/include/x86_64-linux-gnu/asm && ! -e /usr/include/asm ]]; then
  sudo ln -sf /usr/include/x86_64-linux-gnu/asm /usr/include/asm
  ok "asm/types.h symlink"
fi

if have docker; then
  ok "docker already installed"
else
  # Ubuntu's docker package lags so use the upstream repo
  log "docker"
  sudo install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    | sudo tee /etc/apt/keyrings/docker.asc > /dev/null
  sudo chmod a+r /etc/apt/keyrings/docker.asc

  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
    | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

  sudo apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    docker-ce docker-ce-cli containerd.io \
    docker-buildx-plugin docker-compose-plugin

  sudo usermod -aG docker "$USER"
fi

log "container stdout log limits"
# Separate to the bind mounted honeypot logs and these fill disks during scaling runs
sudo tee /etc/docker/daemon.json > /dev/null <<'JSON'
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}
JSON
sudo systemctl restart docker

if have go; then
  ok "go already installed: $(go version)"
else
  log "go, current stable"
  GO_VER="$(curl -fsSL 'https://go.dev/dl/?mode=json' | jq -r '.[0].version')"
  GO_ARCH="$(dpkg --print-architecture)"
  GO_TAR="${GO_VER}.linux-${GO_ARCH}.tar.gz"

  curl -fsSLO "https://go.dev/dl/${GO_TAR}"
  sudo rm -rf /usr/local/go
  sudo tar -C /usr/local -xzf "$GO_TAR"
  rm -f "$GO_TAR"

  if ! grep -q '/usr/local/go/bin' "$HOME/.bashrc"; then
    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> "$HOME/.bashrc"
  fi
  export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin"
fi

log "done"
cat <<'NOTE'

  log out and back in for docker group membership, then:

      docker run --rm hello-world
      make check

  this vm has NAT only. no port forwarding, no bridged adapter.

NOTE
