# AF_XDP Server

## Prerequisites
### Ubuntu
 - [clang](https://apt.llvm.org/) > 8
 - [llc](https://apt.llvm.org/) > 8
 - Install other deps
```bash
    sudo apt install -y make gcc libssl-dev bc libelf-dev gcc-multilib libncurses5-dev git pkg-config libmnl0 bison flex
```
### Fedora 31
```bash
    sudo yum install -y rsync wget make clang llvm gcc openssl-devel bc elfutils-libelf-devel glibc-devel ncurses-devel git pkg-config libmnl bison flex
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
```

## Installation
### Build with dynamic libs
```bash
    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/lib/modules/<KERNEL VERSION>/build/tools/lib/bpf/
    git clone https://git.uniberg.com/tim.fehr/xdp.git
    cd xdp
    nano Makefile   #Change NETDEVICE in line 1
    make
    #To build and run
    make run
```
### Build with static libs
```bash
    git clone https://git.uniberg.com/tim.fehr/xdp.git
    cd xdp
    nano Makefile   #Change NETDEVICE in line 1
    make static
    #To build and run
    make run_static
```