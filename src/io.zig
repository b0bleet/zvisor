const std = @import("std");
const utils = @import("utils.zig");
const serial = @import("devices/serial.zig");
const i8042dev = @import("devices/i8042.zig");
const vfio_pci = @import("devices/vfio_pci.zig");
const console_controller = @import("console_controller.zig");
const interrupt_controller = @import("devices/interrupt_controller.zig");
const interrupt = @import("interrupt.zig");
const log = std.log.scoped(.io);
const InterruptManager = interrupt.InterruptManager;
const assert = std.debug.assert;
const expect = std.testing.expect;
const os = std.os;

const ConsoleController = console_controller.ConsoleController;
const ConsoleMode = console_controller.ConsoleMode;
const SerialDevice = serial.SerialDevice;
const i8042Device = i8042dev.i8042Device;
const InterruptController = interrupt_controller.InterruptController;

pub extern fn cfmakeraw(*std.os.termios) void;

pub const IoDevType = enum {
    Mmio,
    Pmmio,
};

pub const IoReqType = enum {
    Read,
    Write,
};

const VTable = struct {
    read: ?*const fn (*anyopaque, u64, u64, []u8) anyerror!void,
    write: ?*const fn (*anyopaque, u64, u64, []u8) anyerror!void,
};

pub const Device = struct {
    base: u64,
    size: u64,

    deinit: ?*const fn (*anyopaque) void,
    ptr: *anyopaque,
    vtable: *const VTable = undefined,
};

pub const DeviceControl = struct {
    const Self = @This();

    bus: std.ArrayList(Device) = undefined,
    allocator: std.mem.Allocator = undefined,
    pub fn init(allocator: std.mem.Allocator) anyerror!Self {
        const devices_count_max: u16 = 0xffff;
        const dev_bus = try std.ArrayList(Device).initCapacity(allocator, devices_count_max);
        errdefer dev_bus.deinit();

        return Self{
            .allocator = allocator,
            .bus = dev_bus,
        };
    }

    pub fn add_dev(self: *Self, dev: Device) anyerror!void {
        try self.bus.append(dev);
    }

    pub fn find_dev(self: *const Self, base: u64) ?Device {
        for (self.bus.items) |b| {
            if (b.base <= base and base <= b.size) {
                return b;
            }
        }
        return null;
    }

    pub fn handle_dev(_: *const Self, port: u64, dev: Device, direction: IoReqType, data: [*]u8, size: usize) anyerror!void {
        const slice_data = data[0..size];
        switch (direction) {
            .Read => {
                if (dev.vtable.read) |read| return try read(dev.ptr, port -% dev.base, dev.base, slice_data);
            },
            .Write => {
                if (dev.vtable.write) |write| return try write(dev.ptr, port -% dev.base, dev.base, slice_data);
            },
        }
        utils.fatal("Invalid IO/MMIO request: port {} direction: {}\n", .{ port, direction });
    }

    pub fn deinit(self: *Self) void {
        for (self.bus.items) |*dev| {
            if (dev.deinit) |destroy| destroy(dev.ptr);
            self.allocator.destroy(dev);
        }
        self.bus.deinit();
    }
};

pub const DeviceManager = struct {
    allocator: std.mem.Allocator,
    io_bus: DeviceControl,
    mmio_bus: DeviceControl,
    console_handle: ?ConsoleController,
    intr_manager: *InterruptManager,

    pub fn init(allocator: std.mem.Allocator, intr_manager: *InterruptManager) !DeviceManager {
        return DeviceManager{
            .allocator = allocator,
            .console_handle = null,
            .io_bus = try DeviceControl.init(allocator),
            .mmio_bus = try DeviceControl.init(allocator),
            .intr_manager = intr_manager,
        };
    }

    pub fn create_devices(self: *@This(), console_mode: ConsoleMode) anyerror!void {
        var i8042_dev = self.allocator.create(i8042Device) catch |err| return err;
        errdefer self.allocator.destroy(i8042_dev);
        i8042_dev.* = i8042Device.init();
        try self.io_bus.add_dev(i8042_dev.dev());

        var intr_dev = self.allocator.create(InterruptController) catch |err| return err;
        errdefer self.allocator.destroy(intr_dev);
        intr_dev.* = interrupt_controller.InterruptController.init(interrupt_controller.APIC_START);
        try self.mmio_bus.add_dev(intr_dev.dev());

        var serial_dev = self.allocator.create(SerialDevice) catch |err| return err;
        errdefer self.allocator.destroy(serial_dev);
        serial_dev.* = serial.SerialDevice.init(self.allocator, self.intr_manager);
        try self.io_bus.add_dev(serial_dev.dev());

        switch (console_mode) {
            .Tty => {
                const stdin = std.io.getStdIn().handle;
                try self.setup_tty(stdin);
            },
            else => @panic("unsupported console mode"),
        }

        var console_control = try ConsoleController.init(console_mode, serial_dev);
        if (console_control) |*console| {
            self.console_handle = console.*;
            try console.start_thread();
        } else {
            log.warn("unable to initialize console manager\n", .{});
        }
    }

    pub fn handle_dev_req(
        self: *@This(),
        devtype: IoDevType,
        reqtype: IoReqType,
        addr: u64,
        data: [*]u8,
        len: usize,
    ) anyerror!void {
        switch (devtype) {
            .Mmio => {
                if (self.mmio_bus.find_dev(addr)) |dev| {
                    try self.mmio_bus.handle_dev(addr, dev, reqtype, data, len);
                }
            },
            .Pmmio => {
                const port = @intCast(u16, addr);
                if (self.io_bus.find_dev(port)) |dev| {
                    try self.io_bus.handle_dev(port, dev, reqtype, data, len);
                }
            },
        }
    }

    pub fn setup_tty(self: *@This(), fd: std.os.fd_t) !void {
        // set up raw mode for terminal
        try self.modify_mode(fd, cfmakeraw);
    }

    pub fn deinit(self: *@This()) void {
        self.io_bus.deinit();
        self.mmio_bus.deinit();
    }

    fn modify_mode(_: *@This(), fd: os.fd_t, comptime f: fn (*os.termios) callconv(.C) void) !void {
        if (os.isatty(fd) != true) {
            return;
        }
        const orig_term = try os.tcgetattr(fd);
        var term = orig_term;
        f(&term);
        try os.tcsetattr(fd, std.os.TCSA.NOW, term);
    }
};

test "devices" {}
