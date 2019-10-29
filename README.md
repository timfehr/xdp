# AF_XDP Server

## Prerequisites
 - [clang](https://apt.llvm.org/) > 8
 - [llc](https://apt.llvm.org/) > 8
 - Install other deps
```bash
    sudo apt install -y make gcc libssl-dev bc libelf-dev libpcap-dev gcc-multilib libncurses5-dev git pkg-config libmnl0 bison flex graphviz ansible iperf iperf3
```

### Install modified kernel
```bash
    #Download Kernel
    wget https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.3.7.tar.xz
    tar xf linux-5.3.7.tar.xz
    cd linux-5.3.7
    #Build kernel
    make localmodconfig
    make -j $(nproc) # build on all cpu cores
    sudo make modules_install headers_install install
    #Boot into new kernel
    sudo grub-set-default 0
    sudo reboot
```
### Build and link BPF libs
```bash
    make -C /lib/modules/$(uname -r)/build/tools/lib/bpf/
    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/lib/modules/<KERNEL VERSION>/build/tools/lib/bpf/
```

## Installation
```bash
    git clone https://git.uniberg.com/tim.fehr/xdp.git
    cd xdp
    nano Makefile   #Change NETDEVICE in line 1
    make
    #To build and run
    make run
```