#pragma once

#include "common.h"

#include <linux/in.h>
#include <linux/ip.h>

#define IP_MF		0x2000
#define IP_OFFMASK	0x1FFF

static BPF_INLINE int parse_ip4(
	void *ptr, void *end, struct in_addr *src, struct in_addr *dst, uint64_t *off)
{
	struct iphdr *hdr = ptr;

	if (ptr + sizeof(struct iphdr) > end) {
		return -1;
	}

	memcpy(src, &hdr->saddr, sizeof(*src));
	memcpy(dst, &hdr->daddr, sizeof(*dst));
	*off = hdr->ihl << 2;

	// Explicitly ban fragmentation.
	if ((hdr->frag_off & ntohs(IP_MF)) || (hdr->frag_off & ntohs(IP_OFFMASK))) {
		return -1;
	}

	return hdr->protocol;
}
