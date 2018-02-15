#pragma once

#include <iproute2/bpf_api.h>

#define BPF_INLINE    __attribute__((always_inline)) inline
#define BPF_SEC(NAME) __attribute__((section(NAME), used))

#define BPF_STR(v) #v
#define BPF_GRAFT(K, V) BPF_SEC(BPF_STR(K) "/" BPF_STR(V))

// XDP-specific tail call helper.
static void (*xdp_tail_call)(struct xdp_md *ctx, void *map, uint32_t index)
	= (void*)BPF_FUNC_tail_call;

// Forward the given frame to the next ruleset in the chain.
BPF_INLINE int forward(struct xdp_md *ctx);
