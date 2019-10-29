# AF_XDP Server
## Folder structure:
 - lib: Library
 - example: XDP server example
 
## Prerequisites
### Install modified kernel
```bash
#Download Kernel
    wget https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.3.7.tar.xz
    tar xf linux-5.3.7.tar.xz
    cd linux-5.3.7
#Build kernel
    make localmodconfig #Just hit enter for every question
    make -j $(nproc) #build on all cpu cores
    sudo make modules_install headers_install install
#Boot into new kernel
    sudo grub-set-default 0
    sudo reboot
```
### Build and link BPF libs
```bash
    make -C /lib/modules/$(uname -r)/build/tools/lib/bpf/
```