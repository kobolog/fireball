#include "common.h"

#include "lib/eth.h"
#include "lib/ip4.h"
#include "lib/ip6.h"

BPF_LICENSE("GPL");

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

BPF_GRAFT(CHAIN_TID, 0) int rs0(struct xdp_md *ctx)
{
	return forward(ctx);
}

BPF_GRAFT(CHAIN_TID, 1) int rs1(struct xdp_md *ctx)
{
	return XDP_PASS;
}

// Per-CPU ruleset iterator.
BPF_SEC(ELF_SECTION_MAPS) struct bpf_elf_map iterator = {
	.type		= BPF_MAP_TYPE_PERCPU_ARRAY,
	.size_key	= sizeof(int),
	.size_value	= sizeof(int),
	.max_elem	= 1,
	.pinning	= PIN_NONE,
};

BPF_INLINE int forward(struct xdp_md *ctx)
{
	const int idx = 0;

	int *it = (int*)map_lookup_elem(&iterator, &idx);
	if (!it) {
		return XDP_ABORTED;
	}

	// Call the next ruleset.
	xdp_tail_call(ctx, &chain, (*it)++);

	// Default action is to drop all.
	return XDP_DROP;
}

BPF_SEC(ELF_SECTION_PROG) int start(struct xdp_md *ctx)
{
	uint64_t off;
	uint32_t proto = parse_ethernet(
		(void*)(uint64_t)ctx->data, (void*)(uint64_t)ctx->data_end, &off);

	uint32_t src, dst;
	uint32_t ip_proto;

	switch (proto) {
	case htons(ETH_P_ARP):
		return XDP_PASS;
	case htons(ETH_P_IP):
		ip_proto = parse_ip4(
			(void*)(uint64_t)ctx->data + off, (void*)(uint64_t)ctx->data_end,
			&src, &dst);
		printt("ip4 (proto %u) from %u to %u\n", ip_proto, src, dst);
		break;
	case htons(ETH_P_IPV6):
		break;
	default:
		return XDP_DROP;
	}

	const int idx = 0;

	int *it = (int*)map_lookup_elem(&iterator, &idx);
	if (!it) {
		return XDP_ABORTED;
	}

	// Reset the chain ruleset iterator.
	*it = 0;

	return forward(ctx);
}
