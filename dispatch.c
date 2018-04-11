#include "common.h"

#include "lib/eth.h"
#include "lib/ip4.h"
#include "lib/ip6.h"

BPF_LICENSE("GPL");

enum {
	DISPATCH_DROP,
	DISPATCH_PASS,
};

BPF_SEC(ELF_SECTION_PROG) int handle(struct xdp_md *ctx)
{
	void *ptr = (void*)(uint64_t)ctx->data;
	void *end = (void*)(uint64_t)ctx->data_end;

	uint64_t off;
	uint32_t proto = parse_ethernet(ptr, end, &off);

	switch (proto) {
	case htons(ETH_P_ARP):
		increment(DISPATCH_PASS);
		return XDP_PASS;
	case htons(ETH_P_IP):
	case htons(ETH_P_IPV6):
		break;
	default:
		increment(DISPATCH_DROP);
		return XDP_DROP;
	}

	const int id = 0;

	int *it = (int*)map_lookup_elem(&iterator, &id);
	if (!it) {
		return XDP_ABORTED;
	}

	// Reset the chain ruleset iterator.
	*it = 0;

	return forward(ctx);
}
