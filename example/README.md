# AF_XDP Server example
## Prerequisites
### For Ubuntu
 - [clang](https://apt.llvm.org/) > 8
 - [llc](https://apt.llvm.org/) > 8
 - Install other deps
```bash
    sudo apt install -y make gcc libssl-dev bc libelf-dev gcc-multilib libncurses5-dev git pkg-config libmnl0 bison flex
```
### For Fedora 31
```bash
    sudo yum install -y rsync wget make clang llvm gcc openssl-devel bc elfutils-libelf-devel glibc-devel ncurses-devel git pkg-config libmnl bison flex
```
## Installation
### Build with dynamic libs
```bash
    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/lib/modules/5.3.7/build/tools/lib/bpf/
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