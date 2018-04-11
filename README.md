# Fireball

Fireball is a barebones BPF Firewall. It doesn't depend on anything, you just need a fairly recent `clang` to build it.
There's no userspace control plane yet.

## Design

The essential idea is to have a **main dispatch** attached to an interface that calls **rulesets** one after another until a decision about a packet is made or no rulesets are left, in which case the packet is ignored. Each ruleset is configired independently via object-local BPF maps. The following rulesets are implemented:

* Monitor: counts packets but doesn't make any decisions.
* ICMP: allows through or blocks specified ICMP message types.
* Source: allows through or blocks IPv4 and IPv6 packets with source address matching any of the configured prefixes or addresses.
* Drop: drops all the packets. It's a good idea to seal the chain with this ruleset once everything is configured.

## Build & Use

```
make
```

This will compile the main dispatch and all the rulesets into ELF BPF object files. You can load them up with `ip` and `tc` from the `iproute2` suite, as follows:

```
# ip link set dev ${IFACE} xdp object dispatch.o
# tc exec bpf graft m:globals/chain key 1 obj ruleset/bypass.o type xdp
# tc exec bpf graft m:globals/chain key 0 obj ruleset/source.o type xdp
```

# Optimization Ideas

- [ ] Pre-parse packets into TCP/UDP metadata in the dispatch.
- [ ] Incrementally parse packets in chain steps on demand.
- [ ] Parsing stores pointers to `xdp_md*` instead of copying values out.
