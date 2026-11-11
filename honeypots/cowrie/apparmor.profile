#include <tunables/global>

# a deny list over the default shape, not a path allowlist
# the python environment's file surface is too large to enumerate without guessing
profile apiary-cowrie flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>

  # stream and datagram only, no raw or packet sockets so nothing can craft frames
  network inet stream,
  network inet dgram,
  network inet6 stream,
  network inet6 dgram,
  network unix,
  network netlink raw,

  # runc signals the container to stop it, denying this makes every teardown wait for the kill timeout
  signal (receive) peer=runc,
  signal (receive) peer=unconfined,
  signal (send,receive) peer=apiary-cowrie,

  file,
  umount,

  # the bounding set is already empty, this says the same thing at the lsm layer
  deny capability,

  deny @{PROC}/* w,
  deny @{PROC}/sys/** w,
  deny @{PROC}/sysrq-trigger rwklx,
  deny @{PROC}/mem rwklx,
  deny @{PROC}/kmem rwklx,
  deny @{PROC}/kcore rwklx,
  deny @{PROC}/*/attr/** w,

  deny /sys/** wklx,
  deny /sys/fs/bpf/** rwklx,

  deny /var/run/docker.sock rwklx,
  deny /run/docker.sock rwklx,

  deny mount,
  deny ptrace,
}
