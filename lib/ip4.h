#pragma once

#include "common.h"

#include <linux/in.h>
#include <linux/ip.h>

static BPF_INLINE int parse_ip4(void *ptr, void *end, uint32_t *src, uint32_t *dst, uint64_t *off)
{
	struct iphdr *hdr = ptr;

	if (ptr + sizeof(struct iphdr) > end) {
		return -1;
	}

	*src = hdr->saddr;
	*dst = hdr->daddr;
	*off = hdr->ihl << 2;


	return hdr->protocol;
}
