#include "common.h"

#include <linux/icmp.h>

#include "lib/eth.h"
#include "lib/ip4.h"

BPF_LICENSE("GPL");

struct rule {
	enum action action;
	int         metric;
};

BPF_SEC(ELF_SECTION_MAPS) struct bpf_elf_map rules = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(uint8_t),
	.size_value	= sizeof(struct rule),
	.max_elem	= NR_ICMP_TYPES,
	.pinning	= PIN_OBJECT_NS,
};

static BPF_INLINE action handle_icmp4(void *ptr, void *end)
{
	struct in_addr src, dst;
	uint64_t off;

	int proto = parse_ip4(ptr, end, &src, &dst, &off);
	if (proto < 0) {
		return ERROR;
	}

	if (proto != IPPROTO_ICMP) {
		return DEFER;
	}

	struct icmphdr *hdr = ptr + off;

	if (ptr + off + sizeof(struct icmphdr) > end) {
		return ERROR;
	}

	struct rule *r = map_lookup_elem(&rules, &hdr->type);
	if (!r) {
		return DEFER;
	}

	increment(r->metric);

	// We probably want to verify that the action is valid.
	return r->action;
}

BPF_SEC(ELF_SECTION_PROG) int handle(struct xdp_md *ctx)
{
	void *ptr = (void*)(uint64_t)ctx->data;
	void *end = (void*)(uint64_t)ctx->data_end;

	uint64_t off;
	uint32_t proto = parse_ethernet(ptr, end, &off);

	enum action r = DEFER;

	switch (proto) {
	case htons(ETH_P_IP):
		r = handle_icmp4(ptr + off, end);
		break;
	}

	switch (r) {
	case ERROR: return XDP_DROP;
	case ALLOW: return XDP_PASS;
	case DENY:  return XDP_DROP;
	}
	
	return forward(ctx);
}
