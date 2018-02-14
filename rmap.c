#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>
#include <bcc/libbpf.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

int main() {
	int fd = bpf_obj_get("/sys/fs/bpf/ip/globals/v4_counters");
	if (fd < 0) {
		printf("map open err: %s\n", strerror(errno));
		return 1;
	}

	const int DROPPED_KEY = 0, ALLOWED_KEY = 1;
	uint64_t dropped = 0, allowed = 0;
	int ec = 0;

	ec = bpf_lookup_elem(fd, &DROPPED_KEY, &dropped);
	if (ec != 0) {
		printf("map read err: %s\n", strerror(errno));
		return 1;
	}
	ec = bpf_lookup_elem(fd, &ALLOWED_KEY, &allowed);
	if (ec != 0) {
		printf("map read err: %s\n", strerror(errno));
		return 1;
	}

	printf("DROPPED: %lu, ALLOWED: %lu\n", dropped, allowed);
	return 0;
}
