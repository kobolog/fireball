#pragma once

#include "common.h"

#include <linux/in.h>
#include <linux/ip.h>

static BPF_INLINE int parse_ip4(void *it, void *end, uint32_t *src, uint32_t *dst)
{
	struct iphdr *hdr = it;

	if (it + sizeof(struct iphdr) > end) {
		return -1;
	}

	*src = hdr->saddr;
	*dst = hdr->daddr;

	return hdr->protocol;
}
