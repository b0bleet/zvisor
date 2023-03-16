const std = @import("std");
const utils = @import("utils.zig");
const io = @import("io.zig");
const serial = @import("devices/serial.zig");
const assert = std.debug.assert;
const fs = std.fs;
const os = std.os;
const mem = std.mem;
const File = fs.File;
const DeviceControl = io.DeviceControl;
const IoReqType = io.IoReqType;

pub const MsrEntry = struct {
    index: u32,
    data: u64,
};

pub const VcpuState = struct {
    cpu_id: u32,
    msrs: std.ArrayList(MsrEntry),
};

const mib_unit = 1024 * 1024;
const gib_unit = 1024 * 1024 * 1024;

pub const Vm = struct {
    const Self = @This();

    io_bus: DeviceControl = DeviceControl{},
    mmio_bus: DeviceControl = DeviceControl{},
    fw_phys_mem_area: u20 = 0xf0000,
    /// Allocated memory region for virtual machine
    vm_mem_ptr: []align(mem.page_size) u8 = undefined,
    /// Default VM memory size is 512 MB
    /// that will be extended via command-line argument.
    vm_mem_size: usize = (512 * 1024 * 1024), // 512 MiB
    fw_mem_size: usize = undefined,
    /// Allocate memory area for binary file.
    /// Then extract firmware binary file and filling
    /// allocated memory area with that binary file
    vcpu_state: std.ArrayList(VcpuState),
    pub fn init(self: *Self, allocator: std.mem.Allocator, fw: []const u8, mem_size: ?[]const u8) !void {
        if (mem_size) |size| {
            const size_val = std.fmt.parseInt(u64, size[0 .. size.len - 1], 10) catch |err| switch (err) {
                error.InvalidCharacter => @panic("Invalid character for memory size"),
                else => return err,
            };
            const size_as_unit = switch (size[size.len - 1]) {
                'G' => (size_val * gib_unit),
                'M' => (size_val * mib_unit),
                else => unreachable,
            };
            self.vm_mem_size = size_as_unit;
        }
        // Allocate memory for VM with default size
        const vm_mem = try utils.alloc_mem(self.vm_mem_size, null);
        errdefer os.munmap(vm_mem);

        const firmware = try utils.read_file(allocator, fw);
        defer allocator.free(firmware);
        self.fw_mem_size = firmware.len;
        const bios_area = @intToPtr([*]u8, @ptrToInt(vm_mem.ptr) + self.fw_phys_mem_area);
        @memcpy(bios_area, firmware.ptr, firmware.len);

        // Set up VM context for virtualization module (KVM, WHVP)
        self.vm_mem_ptr = vm_mem;
        // Set up `Devices` object and initalize all PCI buses
        self.init_devices(allocator) catch |err| {
            utils.fatal("unable to initialize PCI devices: {}\n", .{err});
        };
    }

    pub fn deinit(self: *Vm) void {
        os.munmap(self.vm_mem_ptr);
        self.io_bus.deinit();
        self.mmio_bus.deinit();

        // iterate over vcpus and deallocate msr entries
        for (self.vcpu_state.items) |vcpu| {
            vcpu.msrs.deinit();
        }
        self.vcpu_state.deinit();
    }

    pub fn io_req(self: *Self, reqtype: IoReqType, port: u16, data: [*]u8, size: usize) anyerror!void {
        if (self.io_bus.find_dev(port)) |dev| {
            try self.io_bus.handle_dev(port, dev, reqtype, data, size);
        }
    }

    pub fn mmio_req(self: *Self, reqtype: IoReqType, addr: u64, data: [*]u8, len: usize) anyerror!void {
        if (self.mmio_bus.find_dev(addr)) |dev| {
            try self.mmio_bus.handle_dev(addr, dev, reqtype, data, len);
        }
    }

    // Initialize MMIO and I/O devices through device controller
    fn init_devices(self: *Self, allocator: std.mem.Allocator) anyerror!void {
        try self.io_bus.init_io_devs(allocator);
        try self.mmio_bus.init_mmio_devs(allocator);
    }
};
