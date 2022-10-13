//+build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifdef asm_inline
#undef asm_inline
#define asm_inline asm
#endif

const volatile long foo = 0;
const volatile long bar = 0;
const volatile long baz = 0;

char LICENSE[] SEC("license") = "GPL";
