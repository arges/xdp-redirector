# xdp redirector

## dependencies
```
sudo apt install clang llvm libelf-dev libpcap-dev build-essential m4 linux-headers-$(uname -r) tcpdump libbpf-dev pwru
sudo ln -s /usr/include/$(uname -m)-linux-gnu/asm /usr/include/asm
```

## quick start

On target machine:
```
make
sudo ./setup
```

From another machine (that can route through target machine NIC):
```
python3 pyudp.py 30
```

## debugging

Run these in separate terminal panes:
```
ip netns exec ns1 xdpdump -i veth1-ns1
sudo cat /sys/kernel/debug/tracing/trace_pipe
pwru --all-kmods --filter-trace-xdp --output-meta dst 10.0.1.2
```
