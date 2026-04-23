# Userspace Router

An exercise in C and working with network data. The goal is to create a multi-threaded program to simulate a router.

## Getting Started

```
git clone https://github.com/ZaneH/userspace-router
cd userspace-router
mkdir build
just build-debug # or `just build-release`
./build/out
```

## Todo

- [x] Parsing
  - [x] TCP/UDP
- [ ] Routing
    - [ ] Multi-threading
- [ ] Forwarding
- [ ] Optimizing

## References

- [Cisco NetAcad](https://www.netacad.com/courses/networking-basics)
- [tcpdump](https://www.tcpdump.org/pcap.html)
