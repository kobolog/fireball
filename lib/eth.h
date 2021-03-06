#pragma once

#include "common.h"

#include <linux/if_ether.h>
#include <linux/if_vlan.h>

// According to 802.1AD there can be at most two VLAN headers.
#define MAX_VLAN_HDRS 2

/*
 *      struct vlan_hdr - vlan header
 *      @h_vlan_TCI: priority and VLAN ID
 *      @h_vlan_encapsulated_proto: packet type ID or len
 */
struct vlan_hdr {
        __be16  h_vlan_TCI;
        __be16  h_vlan_encapsulated_proto;
};

static BPF_INLINE int parse_ethernet(void *ptr, void *end, uint64_t *off)
{
	struct ethhdr *eth = ptr;
	uint64_t len = sizeof(struct ethhdr);

	if (ptr + len > end) {
		return -1;
	}

	uint16_t proto = eth->h_proto;

	// Strip off VLAN headers.
	#pragma unroll
	for (int i = 0; i < MAX_VLAN_HDRS; i++) {
		if (proto != htons(ETH_P_8021Q) && proto != htons(ETH_P_8021AD)) {
			break;
		}

		struct vlan_hdr *vhdr = ptr + len;
		len += sizeof(struct vlan_hdr);

		if (ptr + len > end) {
			return -1;
		}

		proto = vhdr->h_vlan_encapsulated_proto;
	}

	*off = len;
	return proto;
}
