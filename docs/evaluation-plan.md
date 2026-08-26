# evaluation plan

What gets measured and how. Baselines are recorded on first measurement, thresholds set against them later.

## scalability

Max concurrent honeypots, from a spawn loop run until container start fails, noting what binds first. Scale time from the orchestrator deciding to start one to a probe loop connecting, with and without a warm pool. Throughput and latency through the redirect via iperf3 and TCP connect timing, compared against the same path with the BPF program detached. Per-instance CPU and memory from `docker stats`.

Cold start measured: 2.1s, 2.8s, 6.4s across three runs of `cmd/provision`. Timed from ContainerCreate to a successful TCP dial of the honeypot port.

## fidelity

Whether the honeypot looks like the real thing to `nmap -sV`, diffing service and version strings. Whether it holds up under commands it does not implement. Whether one source keeps hitting the same honeypot, comparing container IDs in the session logs. Baseline is the real service on the same host.

## containment

Egress reachability, tabulated in `containment.md` and extended on each rule change. Escape attempts in the same file, one row each. Whether a container's limits hold when stressed from inside.
