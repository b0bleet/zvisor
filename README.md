# Zvisor

<p align="center">
    <img  src="/.github/images/linuxboot.png"
      width="800" border="0" alt="zvisor">
</p>

Zvisor is an open-source hypervisor written in the Zig programming language, which provides a modern and efficient approach to systems programming. Zvisor leverages the KVM (Kernel-based Virtual Machine) virtualization technology, which is built into the Linux kernel, to provide a lightweight and flexible virtualization solution.

One of the key benefits of Zvisor is its use of the Zig programming language. Zig provides a modern and efficient approach to systems programming, with features like memory safety, error handling, and compile-time optimization.

## Getting Started

To get started with the hypervisor, you will need to have Zig (>= 0.11.0) installed on your system. Once you have Zig installed, you can build the hypervisor using the following commands:

```bash
git clone https://github.com/b0bleet/zvisor.git
cd zvisor
zig build
```
This will build the hypervisor and create a binary (`./zig-out/bin/zvisor`) that you can use to start the hypervisor.

Zvisor uses qboot minimal x86 firmware to boot the Linux kernel that's why you have to build qboot before running hypervisor. qboot does PCI setup, IDT setup, E820 table extraction, ACPI tables extraction etc.
```
git clone https://github.com/b0bleet/qboot
meson build && ninja -C build
```

## Running Zvisor
To run Zvisor, you'll need to specify the path to the kernel file, the amount of memory to allocate to the virtual machine, and the initrd file to use.
Here's an example command to run a virtual machine with 2GB of memory:
```bash
./zig-out/bin/zvisor --firmware ./qboot/build/bios.bin \
                      --kernel ./bzImage \
                      --cmdline 'console=ttyS0,115200,8n1 noapic' \
                      --initrd ./initrd \
                      --memory 1G
```
`noapic` option should be passed because, at the moment, Zvisor only supports in-kernel PIC emulation.

## initrd file
An initrd (initial RAM disk) file is a temporary root filesystem that is loaded into memory when the system boots. It's used by the Linux kernel to perform initial tasks like loading necessary drivers, mounting the actual root filesystem, and other early boot tasks. Use BusyBox To generate an initrd file.
