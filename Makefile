CC      = clang
CFLAGS  = -O2 -Wall -g --target=bpf -I include -I .
RS	= drop icmp monitor source

%.o: %.c include/common.h $(wildcard lib/*.h)
	$(CC) $(CFLAGS) -c $< -o $@

all: dispatch.o $(foreach T, $(RS), ruleset/$(T).o)

clean:
	rm -rf *.o ruleset/*.o

.PHONY: all clean
