#include "common.h"

#include "lib/eth.h"
#include "lib/ip4.h"
#include "lib/ip6.h"

BPF_LICENSE("GPL");

#define RULE_TABLE_SIZE 1024

struct prefix_t {
	struct bpf_lpm_trie_key key;
	uint8_t addr[16];
};

BPF_SEC(ELF_SECTION_MAPS) struct bpf_elf_map rules = {
	.type		= BPF_MAP_TYPE_LPM_TRIE,
	.size_key	= sizeof(struct prefix_t),
	.size_value	= sizeof(int),
	.flags		= BPF_F_NO_PREALLOC,
	.max_elem	= RULE_TABLE_SIZE,
	.pinning	= PIN_OBJECT_NS,
};

enum {
	ALLOW,
	DENY,
	DEFER
};

static BPF_INLINE int handle_ip4(void *ptr, void *end)
{
	uint32_t        src, dst;
	struct prefix_t pfx = {};

	if (parse_ip4(ptr, end, &src, &dst) < 0) {
		return DENY;
	}

	pfx.key.prefixlen = 32;
	memcpy(pfx.addr, &src, sizeof(src));

	int *rule = map_lookup_elem(&rules, &pfx);
	if (!rule) {
		return DEFER;
	}

	return *rule;
}

static BPF_INLINE int handle_ip6(void *ptr, void *end)
{
	return DEFER;
}

BPF_SEC(ELF_SECTION_PROG) int handle(struct xdp_md *ctx)
{
	void *ptr = (void*)(uint64_t)ctx->data;
	void *end = (void*)(uint64_t)ctx->data_end;

	uint64_t off;
	uint32_t proto = parse_ethernet(ptr, end, &off);

	int rule = 0;

	switch (proto) {
	case ETH_P_IP:
		rule = handle_ip4(ptr + off, end);
		break;
	case ETH_P_IPV6:
		rule = handle_ip6(ptr + off, end);
		break;
	}

	switch (rule) {
	case ALLOW: return XDP_PASS;
	case DENY:  return XDP_DROP;
	}
	
	return forward(ctx);
}
