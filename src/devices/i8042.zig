const std = @import("std");
const io = @import("../io.zig");

const Device = io.Device;

pub const i8042Device = struct {
    const Self = @This();

    pub fn init() Self {
        return Self{};
    }

    fn read(_: *anyopaque, offset: u64, _: u64, data: []u8) anyerror!void {
        if (data.len == 1 and offset == 3) {
            data[0] = 0x0;
        } else if (data.len == 1 and offset == 0) {
            data[0] = 0x20;
        }
    }

    fn write(_: *anyopaque, _: u64, _: u64, _: []u8) !void {}

    pub fn dev(
        self: *@This(),
    ) Device {
        return Device{
            .deinit = null,
            .base = 0x61,
            .size = 0x65,
            .ptr = self,
            .vtable = &.{
                .read = read,
                .write = write,
            },
        };
    }
};
