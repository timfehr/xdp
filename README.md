# AF_XDP Server

## Prerequisites
```bash
    sudo apt install -y make gcc libssl-dev bc libelf-dev libpcap-dev clang gcc-multilib llvm libncurses5-dev git pkg-config libmnl0 bison flex graphviz ansible iperf iperf3
```

### For Kernel 4.19
```bash
    #Build Kernel
    wget https://cdn.kernel.org/pub/linux/kernel/v4.x/linux-4.19.9.tar.xz
    tar xf linux-4.19.9.tar.xz
    cd linux-4.19.9
    make localmodconfig
    make -j4 # build on 4 Threads
    sudo make modules_install headers_install install

    Build BPF libs
    cd /lib/modules/$(shell uname -r)/build/tools/lib/bpf/
    make
```

### For Kernel >= 5

Not working atm, because of linker error, hopefully it will be fixed the next few days

## Installation
```bash
    git clone https://git.uniberg.com/tim.fehr/afxdp-packet-processor.git
    cd afxdp-packet-processor/server_afxdp
    make
    #To build and run
    make run
```