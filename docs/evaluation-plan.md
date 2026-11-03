# evaluation plan

What gets measured and how. Baselines are recorded on first measurement, thresholds set against them later.

## scalability

Max concurrent honeypots, from a spawn loop run until container start fails, noting what binds first. Scale time from the orchestrator deciding to start one to a probe loop connecting, with and without a warm pool. Throughput and latency through the redirect via iperf3 and TCP connect timing, compared against the same path with the BPF program detached. Per-instance CPU and memory from `docker stats`.

Cold start measured: 2.1s, 2.8s, 6.4s across three runs of `cmd/provision`. Timed from ContainerCreate to a successful TCP dial of the honeypot port.

## fidelity

Whether the honeypot looks like the real thing to `nmap -sV`, diffing service and version strings. Whether it holds up under commands it does not implement. Whether one source keeps hitting the same honeypot, comparing container IDs in the session logs. Baseline is the real service on the same host.

## containment

Egress reachability, tabulated in `containment.md` and extended on each rule change. Escape attempts in the same file, one row each. Whether a container's limits hold when stressed from inside.

## where each metric lives

- panels: honeypot count by state, unserved flows, open sessions, scaling actions against promotions, promotion latency, fleet cpu and memory, attacks over time, unique sources, credential attempts, commands executed, events by class
- measured once and written up rather than panelled: max concurrent honeypots, cold start against warm promotion, redirect throughput and connect latency against the detached path, nmap service and version diffs, egress and escape results
- per instance cpu and memory stay out of prometheus, the instance id would be an unbounded label. docker stats on demand instead
- redirect latency is a per packet figure inside the bpf program and is not exported, it comes from the measurement harness
