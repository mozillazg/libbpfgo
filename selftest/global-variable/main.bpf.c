//+build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifdef asm_inline
#undef asm_inline
#define asm_inline asm
#endif

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct event_t {
	u64 a;
	char c[6];
};

const volatile u32 abc = 1;
const volatile u32 efg = 2;
const volatile struct event_t foobar = {};
const volatile long foo = 3;
volatile int bar = 4;
const volatile int baz SEC(".rodata.baz") = 5;
const volatile int qux SEC(".data.qux") = 6;

char LICENSE[] SEC("license") = "GPL";

