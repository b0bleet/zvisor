const std = @import("std");
const utils = @import("utils.zig");
const serial = @import("devices/serial.zig");
const i8042dev = @import("devices/i8042.zig");
const console_controller = @import("console_controller.zig");
const interrupt_controller = @import("devices/interrupt_controller.zig");
const interrupt = @import("interrupt.zig");
const InterruptManager = interrupt.InterruptManager;
const assert = std.debug.assert;
const expect = std.testing.expect;

const ConsoleController = console_controller.ConsoleController;
const SerialDevice = serial.SerialDevice;
const i8042Device = i8042dev.i8042Device;
const InterruptController = interrupt_controller.InterruptController;

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
    devices_count_max: u16 = 0xffff,
    allocator: std.mem.Allocator = undefined,
    console_handle: ?ConsoleController = null,
    pub fn init_io_devs(self: *Self, allocator: std.mem.Allocator, intr_manager: *InterruptManager) anyerror!void {
        self.allocator = allocator;
        self.bus = try std.ArrayList(Device).initCapacity(allocator, self.devices_count_max);
        errdefer self.bus.deinit();

        try self.start_console_dev(allocator, intr_manager);

        var i8042_dev = allocator.create(i8042Device) catch |err| return err;
        errdefer allocator.destroy(i8042_dev);
        i8042_dev.* = i8042Device.init();
        try self.add_dev(i8042_dev.dev());
    }

    pub fn init_mmio_devs(self: *Self, allocator: std.mem.Allocator) anyerror!void {
        self.allocator = allocator;
        self.bus = try std.ArrayList(Device).initCapacity(allocator, self.devices_count_max);
        errdefer self.bus.deinit();

        var intr_dev = allocator.create(InterruptController) catch |err| return err;
        errdefer allocator.destroy(intr_dev);
        intr_dev.* = interrupt_controller.InterruptController.init(interrupt_controller.APIC_START);
        try self.add_dev(intr_dev.dev());
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
        utils.fatal("Invalid IO request: port {} direction: {}\n", .{ port, direction });
    }

    pub fn deinit(self: *Self) void {
        for (self.bus.items) |*dev| {
            if (dev.deinit) |destroy| destroy(dev.ptr);
            self.allocator.destroy(dev);
        }
        self.bus.deinit();
    }

    fn start_console_dev(self: *Self, allocator: std.mem.Allocator, intr_manager: *InterruptManager) !void {
        var serial_dev = allocator.create(SerialDevice) catch |err| return err;
        errdefer allocator.destroy(serial_dev);
        serial_dev.* = serial.SerialDevice.init(allocator, intr_manager);
        try self.add_dev(serial_dev.dev());

        var console_control = try ConsoleController.init(.Tty, serial_dev);
        if (console_control) |*console| {
            self.console_handle = console.*;
            try console.start_thread();
        }
    }
};

test "devices" {}
