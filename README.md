# Fireball

Fireball is a barebones BPF Firewall. It doesn't depend on anything, you just need a fairly recent `clang` to build it.
There's no userspace control plane yet.

## Design

The essential idea is to have a **main dispatch** attached to an interface that calls **rulesets** one after another until a decision about a packet is made or no rulesets are left, in which case the packet is dropped. Each ruleset is configired independently via object-local BPF maps. The following rulesets are implemented:

* Bypass: lets all the packets through. If you don't have any rules configured yet, it's a good idea to have this ruleset at the end of the chain until all whitelists are in place.
* ICMP: allows through or blocks specified ICMP message types.
* Source: allows through or blocks IPv4 and IPv6 packets with source address matching any of the configured prefixes or a full addresses.
* Monitor: counts packets but doesn't make any decisions.

## Build & Use

```
make
```

This will compile the main dispatch and all the rulesets into ELF BPF object files. You can load them up with `ip` and `tc` from the `iproute2` suite, as follows:

```
# ip link set dev ${IFACE} xdp object dispatch.o
# tc exec bpf graft m:globals/chain key 1 obj bypass.o type xdp
# tc exec bpf graft m:globals/chain key 0 obj source.o type xdp
```

Note that the main dispatch will install an implicit **allow-all** rule in at the beginning of the chain to avoid blocking you from your own host, since the default behavior is to drop all non-whitelisted traffic.
