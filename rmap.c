#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>
#include <bcc/libbpf.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

int main(int argc, char* argv[]) {
	int fd = bpf_obj_get(argv[1]);
	if (fd < 0) {
		printf("map open err: %s\n", strerror(errno));
		return 1;
	}

	int id = 0;
	uint64_t v[16];
	int ec = 0;

	ec = bpf_lookup_elem(fd, &id, &v);
	if (ec != 0) {
		printf("map read err: %s\n", strerror(errno));
		return 1;
	}

	printf("v[0] = %lu v[1] = %lu\n", v[0], v[1]);
	return 0;
}
