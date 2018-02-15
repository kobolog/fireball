#include "common.h"

BPF_LICENSE("GPL");

// Holds the probe chain.
BPF_SEC(ELF_SECTION_MAPS) struct bpf_elf_map chain = {
	.type		= BPF_MAP_TYPE_PROG_ARRAY,
	.size_key	= sizeof(int),
	.size_value	= sizeof(int),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= 32,
};

// Per-CPU probe iterator.
BPF_SEC(ELF_SECTION_MAPS) struct bpf_elf_map iterator = {
	.type		= BPF_MAP_TYPE_PERCPU_ARRAY,
	.size_key	= sizeof(int),
	.size_value	= sizeof(int),
	.pinning	= PIN_NONE,
	.max_elem	= 1,
};

BPF_INLINE int forward(struct xdp_md *ctx)
{
	const int idx = 0;

	int *it = (int*)map_lookup_elem(&iterator, &idx);
	if (!it) {
		return XDP_ABORTED;
	}

	// Call the next probe.
	xdp_tail_call(ctx, &chain, (*it)++);

	// Default action is to drop.
	return XDP_PASS;
}

BPF_SEC("prog") int start(struct xdp_md *ctx)
{
	const int idx = 0;

	int *it = (int*)map_lookup_elem(&iterator, &idx);
	if (!it) {
		return XDP_ABORTED;
	}

	// Reset the chain probe iterator.
	*it = 0;

	return forward(ctx);
}
