#pragma once

#include "common.h"

#include <linux/in.h>
#include <linux/ip.h>

#define IP_MF	   0x2000
#define IP_OFFMASK 0x1FFF

static BPF_INLINE int parse_ip4(void *ptr, void *end, uint32_t *src, uint32_t *dst, uint64_t *off)
{
	struct iphdr *hdr = ptr;

	if (ptr + sizeof(struct iphdr) > end) {
		return -1;
	}

	*src = hdr->saddr;
	*dst = hdr->daddr;
	*off = hdr->ihl << 2;

	// Explicitly ban fragmentation.
	if (hdr->frag_off & IP_MF || (hdr->frag_off & IP_OFFMASK) != 0) {
		return -1;
	}

	return hdr->protocol;
}
