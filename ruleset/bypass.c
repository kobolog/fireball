#include "common.h"

BPF_LICENSE("GPL");

BPF_SEC(ELF_SECTION_PROG) int start(struct xdp_md *ctx) {
	return XDP_PASS;
}
