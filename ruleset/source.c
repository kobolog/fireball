#include "common.h"

#include "lib/eth.h"
#include "lib/ip4.h"
#include "lib/ip6.h"

BPF_LICENSE("GPL");

struct pfx_v4_t {
	struct bpf_lpm_trie_key key;
	struct in_addr          src;
};

struct pfx_v6_t {
	struct bpf_lpm_trie_key key;
	struct in6_addr         src;
};

struct rule {
	enum action action;
	int         metric;
};

#define RULE_TABLE_SIZE 1024

BPF_SEC(ELF_SECTION_MAPS) struct bpf_elf_map rules_v4 = {
	.type		= BPF_MAP_TYPE_LPM_TRIE,
	.size_key	= sizeof(struct pfx_v4_t),
	.size_value	= sizeof(struct rule),
	.flags		= BPF_F_NO_PREALLOC,
	.max_elem	= RULE_TABLE_SIZE,
	.pinning	= PIN_OBJECT_NS,
};

BPF_SEC(ELF_SECTION_MAPS) struct bpf_elf_map rules_v6 = {
	.type		= BPF_MAP_TYPE_LPM_TRIE,
	.size_key	= sizeof(struct pfx_v6_t),
	.size_value	= sizeof(struct rule),
	.flags		= BPF_F_NO_PREALLOC,
	.max_elem	= RULE_TABLE_SIZE,
	.pinning	= PIN_OBJECT_NS,
};

static BPF_INLINE enum action handle_ip4(void *ptr, void *end)
{
	struct in_addr  src, dst;
	uint64_t	off;
	struct pfx_v4_t pfx = {};

	if (parse_ip4(ptr, end, &src, &dst, &off) < 0) {
		return ERROR;
	}

	pfx.key.prefixlen = 32;
	memcpy(&pfx.src, &src, sizeof(pfx.src));

	struct rule *r = map_lookup_elem(&rules_v4, &pfx);
	if (!r) {
		return DEFER;
	}

	increment(r->metric);

	// We probably want to verify that the action is valid.
	return r->action;
}

static BPF_INLINE enum action handle_ip6(void *ptr, void *end)
{
	struct in6_addr src, dst;
	uint64_t	off;
	struct pfx_v6_t pfx = {};

	if (parse_ip6(ptr, end, &src, &dst, &off) < 0) {
		return ERROR;
	}

	pfx.key.prefixlen = 128;
	memcpy(&pfx.src, &src, sizeof(pfx.src));

	struct rule *r = map_lookup_elem(&rules_v6, &pfx);
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
		r = handle_ip4(ptr + off, end);
		break;
	case htons(ETH_P_IPV6):
		r = handle_ip6(ptr + off, end);
		break;
	}

	switch (r) {
	case ERROR: return XDP_DROP;
	case ALLOW: return XDP_PASS;
	case DENY:  return XDP_DROP;
	case DEFER: return XDP_PASS;
	}
	
	return forward(ctx);
}

