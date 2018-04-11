#include "common.h"

BPF_LICENSE("GPL");

enum {
	MONITOR_PASS,
};

BPF_SEC(ELF_SECTION_PROG) int handle(struct xdp_md *ctx)
{
	increment(MONITOR_PASS);
	return forward(ctx);
}
