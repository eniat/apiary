# orchestrator

Contracts in `orchestrator/internal/apiary`, decisions in `orchestrator/internal/policy`.

| component | owns | talks to |
|---|---|---|
| metrics | the scaling signal | docker stats, cowrie logs, bpf maps |
| policy | up or down or hold | nothing |
| provisioner | container lifecycle and the warm pool | docker |
| registrar | redirect map rows | bpf maps |
| reaper | archive then destroy | docker and the log store |

One tick: metrics builds a `Snapshot`, policy returns an `Action`, provisioner or reaper carries it out.

- Scale up is promote then verify then register. Register last or traffic arrives before the honeypot is ready
- Teardown is deregister then archive then destroy. Deregister first or rows point at a dead container
- Policy tolerates an action not happening. The reaper refuses to destroy a honeypot holding a session
- `policy` imports only the standard library. Anything it needs goes in `Snapshot`
- Session counts come from the cowrie json log so every honeypot needs its log dir bind mounted. Silence past a window counts as closed or one lost close event pins a honeypot alive
- The loop promotes and refills. Binding an attacker to a honeypot is event driven off a detection not something a tick decides
