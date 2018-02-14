#include <iproute2/bpf_api.h>

#define BPF_INLINE    __attribute__((always_inline))
#define BPF_SEC(NAME) __attribute__((section(NAME), used))

// Holds all types of possible rule actions.
struct bpf_elf_map BPF_SEC(ELF_SECTION_MAPS) actions = {
	.type		= BPF_MAP_TYPE_PROG_ARRAY,
	.size_key	= sizeof(int),
	.size_value	= sizeof(int),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= 256,
};

// Holds the probe chain.
struct bpf_elf_map BPF_SEC(ELF_SECTION_MAPS) chain = {
	.type		= BPF_MAP_TYPE_PROG_ARRAY,
	.size_key	= sizeof(int),
	.size_value	= sizeof(int),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= 32,
};

// Per-CPU probe iterator.
struct bpf_elf_map BPF_SEC(ELF_SECTION_MAPS) iterator = {
	.type		= BPF_MAP_TYPE_PERCPU_ARRAY,
	.size_key	= sizeof(int),
	.size_value	= sizeof(int),
	.pinning	= PIN_NONE,
	.max_elem	= 1,
};

// XDP-specific tail call helper.
static void (*xdp_tail_call)(struct xdp_md *xdp, void *map, uint32_t index)
	= (void*)BPF_FUNC_tail_call;

// Possible chain probe actions.
enum action_t { PASS, DROP, CONTINUE };

int BPF_INLINE action(struct xdp_md *xdp, enum action_t action) {
	switch (action) {
	case PASS:
		return XDP_PASS;
	case DROP:
		return XDP_DROP;
	case CONTINUE:
		break;
	}	
	
	const int idx = 0;

	int *it = (int*)map_lookup_elem(&iterator, &idx);
	if (!it) {
		return XDP_ABORTED;
	}

	// Call the next probe.
	xdp_tail_call(xdp, &chain, (*it)++);

	// Default action is to drop.
	return XDP_PASS;
}

int BPF_SEC("filter") start(struct xdp_md *xdp)
{
	const int idx = 0;

	int *it = (int*)map_lookup_elem(&iterator, &idx);
	if (!it) {
		return XDP_ABORTED;
	}

	// Reset the chain probe iterator.
	*it = 0;

	return action(xdp, CONTINUE);
}

BPF_LICENSE("GPL");
