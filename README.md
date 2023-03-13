# zVisor (WIP)

zVisor is an open-source hypervisor written in the Zig programming language, which provides a modern and efficient approach to systems programming. zVisor leverages the KVM (Kernel-based Virtual Machine) virtualization technology, which is built into the Linux kernel, to provide a lightweight and flexible virtualization solution.

One of the key benefits of zVisor is its use of the Zig programming language. Zig provides a modern and efficient approach to systems programming, with features like memory safety, error handling, and compile-time optimization.

## Getting Started

To get started with the hypervisor, you will need to have Zig installed on your system. Once you have Zig installed, you can build the hypervisor using the following commands:

```bash
git clone https://github.com/b0bleet/zvisor.git
cd zvisor
zig build
```
This will build the hypervisor and create a binary (`./zig-out/bin/zvisor`) that you can use to start the hypervisor.

zVisor uses qboot minimal x86 firmware to boot Linux kernel that's why you have to build qboot before running hypervisor:
```
git clone https://github.com/b0bleet/qboot
meson build && ninja -C build
```

## Running zVisor
To run zVisor, you'll need to specify the path to the kernel file, the amount of memory to allocate to the virtual machine, and the initrd file to use.
Here's an example command to run a virtual machine with 2GB of memory:
```bash
./zig-out/bin/zvisor --firmware ./qboot/build/bios.bin \
                      --kernel ./bzImage \
                      --cmdline 'console=ttyS0,115200,8n1' \
                      --initrd ./initrd \
                      --memory 1G
```
