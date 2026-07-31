# 0001: eBPF/TC for the redirect data plane

**Decision:** TC-attached BPF on each container veth, redirect table in a userspace-written map. Fallback is OVS with a controller.

**Why**
- Docker already gives me a veth per container, so no switch or second daemon
- Map is a clean split: userspace writes, kernel reads on the next packet, no reload

**Cost**
- Verifier is the learning curve
- XDP on veth probably drops to generic mode, so throughput numbers are a floor

**Fallback:** OVS trades kernel integration for a much shorter path to working.