# geatu

Geatu is an experimental eBPF-based LSM for keeping out your (maybe) files from unwanted applications.

Geatu uses xattr for security tags.

** WARNING **: Geatu is highly experimental. Security tags may break between versions. Use at your own risk.

## Building
Requires `libbpf`. 

The following command will compile and load the module.

```
cargo libbpf build -d && sudo bpftool prog loadall target/artifact/net.bpf.o /sys/fs/bpf/geatu autoattach && sudo bpftool prog tracelog; sudo rm -r /sys/fs/bpf/geatu
```