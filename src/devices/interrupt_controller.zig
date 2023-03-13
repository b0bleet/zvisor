const std = @import("std");
const io = @import("../io.zig");
const Device = io.Device;

pub const IOAPIC_START: usize = 0xfec0_0000;
pub const IOAPIC_SIZE: usize = 0x20;

pub const APIC_START: usize = 0xfee0_0000;

pub const InterruptController = struct {
    id: []const u8,
    apic_address: usize,

    pub fn init(apic_address: usize) InterruptController {
        return InterruptController{ .id = "ioapic", .apic_address = apic_address };
    }

    pub fn dev(
        self: *@This(),
    ) Device {
        return Device{
            .deinit = null,
            .base = IOAPIC_START,
            .size = (IOAPIC_START + IOAPIC_SIZE),
            .ptr = self,
            .vtable = &.{
                .read = read,
                .write = write,
            },
        };
    }

    fn read(_: *anyopaque, _: u64, _: u64, _: []u8) anyerror!void {}

    fn write(_: *anyopaque, _: u64, _: u64, _: []u8) !void {}
};
