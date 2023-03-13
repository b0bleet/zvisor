const std = @import("std");
const utils = @import("utils.zig");
const io = @import("io.zig");
const serial = @import("devices/serial.zig");
const kvm = @import("kvm.zig");
const interrupt = @import("interrupt.zig");
const c_kvm = @import("root").c_kvm;

const OS = utils.OS;
const Config = @import("root").Config;

const log = std.log.scoped(.zvisor);
const assert = std.debug.assert;
const fatal = utils.fatal;
const fs = std.fs;
const os = std.os;
const mem = std.mem;
const File = fs.File;
const DeviceControl = io.DeviceControl;
const DeviceManager = io.DeviceManager;
const IoReqType = io.IoReqType;
const InterruptManager = interrupt.InterruptManager;

const mib_unit = 1024 * 1024;
const gib_unit = 1024 * 1024 * 1024;

const AccelApic = struct {
    get_klapic: *const fn (*anyopaque) anyerror!LapicState,
    get_klapic_reg: *const fn (*anyopaque, *LapicState, u32) u32,
    set_klapic_reg: *const fn (*anyopaque, *LapicState, u32, u32) void,
    set_klapic: *const fn (*anyopaque, *LapicState) anyerror!void,
    setup_ioapic: *const fn (*anyopaque) anyerror!bool,
};

const AccelVTable = struct {
    apic: ?AccelApic,
    inject_interrupt: *const fn (*anyopaque, irq: u32, level: u32) anyerror!void,
    set_cpuids: *const fn (*anyopaque, cpuids: std.ArrayList(ZvCpuid.Cpuid)) anyerror!void,
};

pub const Accel = struct {
    ptr: *anyopaque,
    vtable: *const AccelVTable = undefined,
};

pub const LapicState = union {
    kvm_lapic: c_kvm.kvm_lapic_state,
    wth: u32,
};

pub const ZvCpuid = struct {
    const Self = @This();

    const CpuidRegs = enum {
        Eax,
        Ebx,
        Ecx,
        Edx,
    };

    pub const Cpuid = struct {
        SetBits: bool = false,
        Function: u32,
        Index: ?u32 = null,
        Flags: ?u32 = null,
        Eax: ?u32 = null,
        Ebx: ?u32 = null,
        Ecx: ?u32 = null,
        Edx: ?u32 = null,
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
        // If the CPUID exists, then remove it.
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

    dev_manager: DeviceManager = undefined,
    intr_manager: *interrupt.InterruptManager = undefined,
    fw_phys_mem_area: u20,
    /// Allocated memory region for virtual machine
    vm_mem_ptr: []align(mem.page_size) u8 = undefined,
    /// Allocate memory area for binary file.
    /// Then extract firmware binary file and filling
    /// allocated memory area with that binary file
    vm_mem_size: usize,
    fw_mem_size: usize = undefined,
    pub fn init(allocator: mem.Allocator, config: Config) !Self {
        const fw_phys_mem_area = 0xf0000;
        const fw = config.firmware;
        const mem_size = config.memory;

        const vm_mem_size = blk: {
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
                break :blk size_as_unit;
            } else {
                break :blk (512 * 1024 * 1024);
            }
        };
        // Allocate memory for VM with default size
        const vm_mem = try utils.alloc_mem(vm_mem_size, null);
        errdefer os.munmap(vm_mem);

        const firmware = try utils.read_file(allocator, fw);
        defer allocator.free(firmware);

        assert(fw_phys_mem_area < vm_mem_size);
        const bios_area = @intToPtr([*]u8, @ptrToInt(vm_mem.ptr) + fw_phys_mem_area);
        @memcpy(bios_area, firmware.ptr, firmware.len);

        return Self{
            .fw_phys_mem_area = fw_phys_mem_area,
            .fw_mem_size = firmware.len,
            .vm_mem_ptr = vm_mem,
            .vm_mem_size = vm_mem_size,
        };
    }

    pub fn run_vm(self: *@This(), allocator: std.mem.Allocator, config: *const Config) anyerror!void {
        // Initialize VM accelerator
        // At the moment KVM will be used by default
        // Initialize KVM context
        var kvm_ctx = kvm.Kvm.init(allocator, self, config.cpus) catch |err| fatal("unable to initialize kvm context: {}", .{err});
        defer kvm_ctx.deinit();
        try kvm_ctx.setup_vm(allocator, config);

        OS.register_signal(OS.sigrtmin(), signal_handler);

        const accel = kvm_ctx.get_accel();
        self.intr_manager = try interrupt.InterruptManager.init(&accel, allocator);
        errdefer allocator.destroy(self.intr_manager);
        const vcpu = accel.vtable;
        if (vcpu.apic == null) {
            log.warn("unable to initialize accelerator APIC\n", .{});
        }
        try self.intr_manager.setup_apic();

        try self.prep_cpuid(allocator, &accel);

        // Set up `Devices` object and initalize all PCI buses
        self.init_devices(allocator) catch |err| utils.fatal("unable to initialize PCI devices: {}\n", .{err});
        defer if (self.dev_manager.console_handle) |console| console.handle.join();
        kvm_ctx.run_vm() catch |err| switch (err) {
            error.FailIoReq => fatal("unable to send ioctl: {}", .{err}),
            error.FailMmioReq => fatal("unable to handle io request: {}", .{err}),
            error.FailVmRun => fatal("unable to run VM: {}", .{err}),
            error.FailGetRegs => fatal("unable to get registers from accelerator: {}", .{err}),
        };
    }

    pub fn deinit(self: *Vm) void {
        os.munmap(self.vm_mem_ptr);
        self.dev_manager.deinit();
        self.intr_manager.deinit();
    }

    // Initialize MMIO and I/O devices with Device Manager
    fn init_devices(self: *Self, allocator: std.mem.Allocator) anyerror!void {
        self.dev_manager = try DeviceManager.init(allocator, self.intr_manager);
        errdefer self.dev_manager.deinit();
        try self.dev_manager.create_devices(.Tty);
    }

    fn prep_cpuid(_: *Self, allocator: std.mem.Allocator, accel: *const Accel) anyerror!void {
        const vcpu = accel.vtable;
        var zvcpuids = ZvCpuid.init(allocator);
        defer zvcpuids.deinit();

        try zvcpuids.set_regs(.{
            .Function = 0x7,
            .Ebx = 0xf0bf47ab,
            .Ecx = 0x405f4e,
            .Edx = 0xac000400,
        });

        try zvcpuids.set_regs(.{
            .Function = 0xa,
        });

        try zvcpuids.set_regs(.{
            .Function = 0x1,
            .SetBits = true,
            .Ecx = 1 << 31, // Enable hypervisor feature
        });

        try vcpu.set_cpuids(accel.ptr, zvcpuids.cpuids);
    }

    fn signal_handler(_: c_int) align(1) callconv(.C) void {
        const stdout = std.io.getStdOut().writer();
        stdout.print("signal handler\n", .{}) catch |err| fatal("{}", .{err});
    }
};
