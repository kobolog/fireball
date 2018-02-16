#include "common.h"

BPF_LICENSE("GPL");

enum counter_id {
	TOTAL,
	__MAX_COUNTER_ID,
};

BPF_SEC(ELF_SECTION_MAPS) struct bpf_elf_map counters = {
	.type		= BPF_MAP_TYPE_PERCPU_ARRAY,
	.size_key	= sizeof(int),
	.size_value	= sizeof(uint64_t),
	.max_elem	= __MAX_COUNTER_ID,
	.pinning	= PIN_OBJECT_NS,
};

BPF_SEC(ELF_SECTION_PROG) int start(struct xdp_md *ctx) {
	const int id = TOTAL;

	uint64_t *c = (uint64_t*)map_lookup_elem(&counters, &id);
	if (!c) {
		return XDP_ABORTED;
	}

	(*c)++;

	return XDP_PASS;
}
