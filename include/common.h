#pragma once

#include <iproute2/bpf_api.h>

#define BPF_INLINE     __attribute__((always_inline)) inline
#define BPF_SEC(TITLE) __attribute__((section(TITLE), used))

#define BPF_STR(v) #v
#define BPF_GRAFT(K, V) BPF_SEC(BPF_STR(K) "/" BPF_STR(V))

// XDP-specific tail call helper.
static void (*xdp_tail_call)(struct xdp_md *ctx, void *map, uint32_t index)
	= (void*)BPF_FUNC_tail_call;

#define CHAIN_TID 0

// Holds the probe chain.
BPF_SEC(ELF_SECTION_MAPS) struct bpf_elf_map chain = {
	.type		= BPF_MAP_TYPE_PROG_ARRAY,
	.size_key	= sizeof(int),
	.size_value	= sizeof(int),
	.max_elem	= 32,
	.id		= CHAIN_TID,
	.pinning	= PIN_GLOBAL_NS,
};

// Per-CPU ruleset iterator.
BPF_SEC(ELF_SECTION_MAPS) struct bpf_elf_map iterator = {
	.type		= BPF_MAP_TYPE_PERCPU_ARRAY,
	.size_key	= sizeof(int),
	.size_value	= sizeof(int),
	.max_elem	= 1,
	.pinning	= PIN_GLOBAL_NS,
};

// Forward the given frame to the next ruleset in the chain.
static BPF_INLINE int forward(struct xdp_md *ctx)
{
	const int id = 0;

	int *it = (int*)map_lookup_elem(&iterator, &id);
	if (!it) {
		return XDP_ABORTED;
	}

	// Call the next ruleset.
	xdp_tail_call(ctx, &chain, (*it)++);

	// Drop if no ruleset could come up with a decision.
	return XDP_DROP;
}
