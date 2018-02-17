#pragma once

#include "common.h"

#include <linux/ipv6.h>
#include <linux/in6.h>

#define MAX_IPV6_OPT_HDRS 8

static BPF_INLINE int parse_ip6_opt_hdr(void *ptr, void *end, uint64_t *off)
{
	struct ipv6_opt_hdr *opt = ptr;

	if (ptr + sizeof(struct ipv6_opt_hdr) > end) {
		return -1;
	}

	*off = 8 + (opt->hdrlen << 3);

	return opt->nexthdr;
}

static BPF_INLINE int parse_ip6(
	void *ptr, void *end, struct in6_addr *src, struct in6_addr *dst, uint64_t *off)
{
	struct ipv6hdr *hdr = ptr;
	uint64_t len = sizeof(struct ipv6hdr), hdrsz = 0;

	if (ptr + len > end) {
		return -1;
	}

	*src = hdr->saddr;
	*dst = hdr->daddr;

	int type = hdr->nexthdr;

	#pragma unroll
	for (int i = 0; i < MAX_IPV6_OPT_HDRS; i++) {
		switch (type) {
		case IPPROTO_HOPOPTS:
		case IPPROTO_ROUTING:
		case IPPROTO_DSTOPTS:
		case IPPROTO_MH:
			type = parse_ip6_opt_hdr(ptr + (len & 0xFFFF), end, &hdrsz);
			len += hdrsz;
			break;

		case IPPROTO_FRAGMENT:
			// Explicitly ban fragmentation.
			return -1;

		case IPPROTO_TCP:
		case IPPROTO_UDP:
		case IPPROTO_ICMPV6:
			*off = len;
			return type;

		default:
			// Got some unknown header type.
			return -1;
		}
	}

	// Too many optional headers.
	return -1;
}
