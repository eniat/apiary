# Apiary

Dynamic honeypot infrastructure that scales the number of live honeypots
to match attacker load, then steers malicious traffic onto them in the
kernel data plane.

## The problem

Static honeypot deployments (T-Pot style) run a fixed fleet. Under low
load you waste resources; under a spike you run out of coverage. The
design tension, from Vrable et al.'s Potemkin farm (2005), is that
**scalability, fidelity and containment pull against each other**. Every
decision here trades one for another, and this repo is a record of which
trades I made and why.

## What "self-scaling" means here

- **Signal:** unserved malicious flows and per-honeypot session load.
- **A scale-up event:** promote a pre-warmed idle honeypot to live and
register its interface with the redirect data plane.
- **A scale-down event:** reap an idle honeypot after a cooldown, but
never mid-session.

## Architecture (intended)

    attacker traffic
          │
          ▼
    [ eBPF/TC redirect ]  ── reads ──▶ redirect map (src IP → honeypot)
          │                                   ▲
          ▼                                   │ registrar writes here
    [ honeypot pool ]  ◀── provisions ── [ orchestrator ]
          │                                   ▲
          ▼                                   │ metrics
    [ log pipeline ]  ─────────────────────────

## Where it is

- Built: isolated lab with containment evidenced, two honeypots with documented telemetry and tested fingerprint vectors, one normalised event shape over both
- Built: kernel redirect with a working return path, so a redirected attacker completes a real session against a honeypot
- Built: darknet and scan detection in the kernel, thresholds chosen from a sweep, flagged sources registered from a ring buffer
- Next: the orchestrator
- Topology in `docs/lab-setup.md`, boundary in `docs/decisions/0002-lab-boundary.md`, metrics in `docs/evaluation-plan.md`, handoff in `docs/writeups/tcp-handoff.md`

## lineage

The warm pool is the same answer Potemkin gave in 2005. That work cloned idle virtual machines copy on write so a honeypot existed before the attacker needed one, because booting on demand lost the connection that triggered it. Containers and eBPF did not exist then and the constraint has not moved. Measured here at twenty cold starts spanning 2.7 to 11.6 seconds against a promotion that is a map write.
