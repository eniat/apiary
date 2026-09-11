# toolchain

Defender only. installed by `scripts/setup.sh` checked by `make check`

- `clang`, `llvm` build BPF objects, bpf2go calls `llvm-strip` from `llvm`
- `libbpf-dev` gives `bpf/bpf_helpers.h`, `libelf-dev` and `zlib1g-dev` are its link deps
- `linux-libc-dev` gives `linux/bpf.h` and the protocol headers. `linux-headers-$(uname -r)` is not needed, its for out-of-tree modules
- bpftool needs `linux-tools-common` and `linux-tools-$(uname -r)`

Compiling for bpf target fails on `asm/types.h` because ubuntu amd64 keeps arch headers under `/usr/include/x86_64-linux-gnu/asm`. setup.sh symlinks them to `/usr/include/asm`. gcc-multilib is the wrong fix.

Kernel 7.0.0-28-generic so the loader attaches with TCX and falls back to a clsact
filter over a pinned program where TCX is unavailable. `APIARY_ATTACH=tc` forces
the fallback. BTF is present so CO-RE works

## redirect map bytes

Key 4B, value 16B. Rejected at any other length.

    key   0a 0a 0a 14
    value ac 1e 00 03  07 00 00 00  56 4c 20 89 79 46  00 00

Addresses network order, ifindex host order, MAC in order, then padding.
