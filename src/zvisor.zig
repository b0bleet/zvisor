const std = @import("std");
const utils = @import("utils.zig");
const io = @import("io.zig");
const serial = @import("devices/serial.zig");
const kvm = @import("kvm.zig");
const Config = @import("root").Config;
const interrupt = @import("interrupt.zig");
const c_kvm = @import("root").c_kvm;

const assert = std.debug.assert;
const fatal = utils.fatal;
const fs = std.fs;
const os = std.os;
const mem = std.mem;
const File = fs.File;
const DeviceControl = io.DeviceControl;
const IoReqType = io.IoReqType;
const InterruptManager = interrupt.InterruptManager;

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

const AccelVTable = struct {
    get_klapic: *const fn (*anyopaque) anyerror!LapicState,
    get_klapic_reg: *const fn (*anyopaque, *LapicState, u32) u32,
    set_klapic_reg: *const fn (*anyopaque, *LapicState, u32, u32) void,
    set_klapic: *const fn (*anyopaque, *LapicState) anyerror!void,
    inject_interrupt: *const fn (*anyopaque, irq: u32, level: u32) anyerror!void,
};

pub const Accel = struct {
    ptr: *anyopaque,
    vtable: *const AccelVTable = undefined,
};

pub const LapicState = union {
    kvm_lapic: c_kvm.kvm_lapic_state,
    wth: u32,
};

const ZvCpuid = struct {
    const Self = @This();

    const CpuidRegs = enum {
        Eax,
        Ebx,
        Ecx,
        Edx,
    };

    pub const Cpuid = struct {
        Function: u32,
        Index: u32,
        Flags: u32,
        Eax: u32,
        Ebx: u32,
        Ecx: u32,
        Edx: u32,
    };

    cpuids: std.ArrayList(Cpuid),
    pub fn init(allocator: std.mem.Allocator) Self {
        const cpuids_list = std.ArrayList(Cpuid).init(allocator);
        errdefer cpuids_list.deinit();

        return Self{
            .cpuids = cpuids_list,
        };
    }

    pub fn set_reg(self: *Self, reg: CpuidRegs, function: u32, val: u32) !void {
        var found = false;

        if (self.cpuids.items.len != 0) {
            for (self.cpuids.items) |*entries| {
                if (entries.Function == function) {
                    found = true;
                    switch (reg) {
                        .Eax => entries.Eax = val,
                        .Ebx => entries.Ebx = val,
                        .Ecx => entries.Ecx = val,
                        .Edx => entries.Edx = val,
                    }
                }
            }
        }

        if (!found) {
            var cpuid = std.mem.zeroInit(Cpuid, .{ .Function = function });
            switch (reg) {
                .Eax => cpuid.Eax = val,
                .Ebx => cpuid.Ebx = val,
                .Ecx => cpuid.Ecx = val,
                .Edx => cpuid.Edx = val,
            }
            try self.cpuids.append(cpuid);
        }
    }

    pub fn set_regs(self: *Self, reg: Cpuid) !void {
        // if cpuid does exist remove then
        if (self.cpuids.items.len != 0) {
            var i: u32 = 0;
            for (self.cpuids.items) |entries| {
                if (entries.Function == reg.Function) {
                    _ = self.cpuids.orderedRemove(i);
                }
                i += 1;
            }
        }

        try self.cpuids.append(reg);
    }

    pub fn deinit(self: *Self) void {
        self.cpuids.deinit();
    }
};

pub const Vm = struct {
    const Self = @This();

    io_bus: DeviceControl = DeviceControl{},
    mmio_bus: DeviceControl = DeviceControl{},
    intr_manager: *interrupt.InterruptManager = undefined,
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
    pub fn init(self: *Self, allocator: std.mem.Allocator, config: Config) !void {
        const fw = config.firmware;
        const mem_size = config.memory;

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
    }

    pub fn run_vm(self: *@This(), allocator: std.mem.Allocator, config: Config) anyerror!void {
        // Initialize VM accelerator
        // At the moment KVM will be used by default
        // Initialize KVM context
        var kvm_ctx = kvm.Kvm.init(allocator, self) catch |err| {
            fatal("unable to initialize kvm context: {}", .{err});
        };
        defer kvm_ctx.deinit();

        kvm_ctx.setup_vm(allocator, config.kernel, config.initrd, config.cmdline) catch |err| {
            fatal("unable to run accelerator: {}", .{err});
        };

        const accel = kvm_ctx.get_accel();

        try interrupt.set_lint(&accel);
        try self.prep_cpuid(allocator);

        self.intr_manager = try interrupt.InterruptManager.init(&accel, allocator);
        errdefer allocator.destroy(self.intr_manager);

        // Set up `Devices` object and initalize all PCI buses
        self.init_devices(allocator) catch |err| {
            utils.fatal("unable to initialize PCI devices: {}\n", .{err});
        };

        kvm_ctx.run_vm() catch |err| {
            fatal("unable to run VM with KVM accelerator: {}", .{err});
        };
    }

    pub fn deinit(self: *Vm) void {
        os.munmap(self.vm_mem_ptr);
        self.io_bus.deinit();
        self.mmio_bus.deinit();
        self.intr_manager.deinit();

        // iterate over vcpus and deallocate msr entries
        if (self.vcpu_state.items.len != 0) {
            for (self.vcpu_state.items) |vcpu| {
                vcpu.msrs.deinit();
            }
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
        try self.io_bus.init_io_devs(allocator, self.intr_manager);
        try self.mmio_bus.init_mmio_devs(allocator);
    }

    fn prep_cpuid(_: *Self, allocator: std.mem.Allocator) anyerror!void {
        var zvcpuids = ZvCpuid.init(allocator);
        defer zvcpuids.deinit();

        try zvcpuids.set_regs(std.mem.zeroInit(ZvCpuid.Cpuid, .{
            .Function = 0x0,
            .Eax = 0x1b,
            .Ebx = 0x756e6547,
            .Ecx = 0x06c65746e,
            .Edx = 0x49656e69,
        }));
    }
};
