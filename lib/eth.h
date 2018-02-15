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

BPF_INLINE int parse_ethernet(void *it, void *end, uint64_t *offset) {
	struct ethhdr *eth = it;
	uint64_t off = sizeof(*eth);

	if (it + off > end) {
		return -1;
	}

	uint16_t proto = ntohs(eth->h_proto);

	// Strip off VLAN headers.
	#pragma unroll
	for (int i = 0; i < MAX_VLAN_HDRS; i++) {
		if (proto != ETH_P_8021Q && proto != ETH_P_8021AD) {
			break;
		}

		struct vlan_hdr *vhdr = it + off;
		off += sizeof(*vhdr);

		if (it + off > end) {
			return -1;
		}

		proto = ntohs(vhdr->h_vlan_encapsulated_proto);
	}

	*offset = off;
	return proto;
}
