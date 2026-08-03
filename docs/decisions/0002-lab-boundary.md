# 0002: lab boundary and threat model

**Defending against:** compromised honeypot pivoting to other hosts, exhausting host resources or attacking third parties.

**Not defending against:** kernel 0-day escape. Everything runs in a disposable VM I can roll back so it is accepted.

**Boundary as built**
- Single VirtualBox VM, NAT adapter only
- One port forward, 127.0.0.1:2200 to guest 22, bound to loopback
- No forward for any honeypot port, so nothing outside the VM can reach container
- Synthetic traffic only, generated locally

**Not yet built:** isolated host only network and a separate attacker VM. Needed later since the BPF map keys on a stable attacker source address.

**Kill switch**
- Guest: `ip link set enp0s3 down`
- Host: `VBoxManage controlvm apiary-defender setlinkstate1 off`

The guide's egress demonstration is deferred until the second VM exists