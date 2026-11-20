# gotchas

## map names truncate at 15 characters

The kernel caps map names at 15. `redirect_targets` is 16 so bpftool reports it as
`redirect_target`. Looking it up by the name in the source finds nothing.

## iproute2 drops unreferenced maps

`tc filter add ... obj` only instantiates maps that instructions reference. A map
defined but never looked up does not appear in `bpftool map show`. The Go loader
creates every map in the object regardless.

## bpf_printk is expensive

Roughly 9300 ns per packet. Remove it before measuring anything.

## grafana stalls for three minutes with no egress

Plugin key retrieval and the app manifest watcher both call grafana.com at start.
With the lab offline the connect blackholes rather than refusing, so the HTTP
server does not answer until the timeout expires. Null routing the host in
`extra_hosts` takes cold start from 180s to 19s. The analytics flags alone do not.

## a stdlib call is not a seccomp canary

`os.times()` returns normally under a profile that omits `times`, so it never
reaches syscall 100 on this libc. Testing whether a syscall is blocked means
invoking it directly, `libc.syscall(100, buf)` through ctypes, and reading the
return and errno. Anything that goes through a library may take another route.
