const std = @import("std");
const io = @import("../io.zig");
const fs = std.fs;
const Device = io.Device;

const LoopSize = 0x40;

const Data: u8 = 0;
const Ier: u8 = 1;
const Iir: u8 = 2;
const Lcr: u8 = 3;
const Mcr: u8 = 4;
const Lsr: u8 = 5;
const Msr: u8 = 6;
const Scr: u8 = 7;

const LsrDataBit: u8 = 0x1;
const LsrEmptyBit: u8 = 0x20;
const LsrIdleBit: u8 = 0x40;

const IirFifoBits: u8 = 0xc0;
const IirNoneBit: u8 = 0x1;
const IirThrBit: u8 = 0x2;
const IirRecvBit: u8 = 0x4;

const IerRecvBit: u8 = 0x1;
const IerThrBit: u8 = 0x2;
const IerFifoBits: u8 = 0x0f;

const InterruptIdentification: u8 = IirNoneBit;
const LineControl: u8 = 0x3;
const LineStatus: u8 = LsrEmptyBit | LsrIdleBit;
const ModemControl: u8 = 0x8;
const ModemStatus: u8 = 0x20 | 0x10 | 0x80;
const BaudDivisor = 12; // 9600 ps

const LcrDlabBit: u8 = 0x80;

const DlabLow: u8 = 0;
const DlabHigh: u8 = 1;

const McrLoopBit: u8 = 0x10;

var m = std.Thread.Mutex{};

pub const SerialDevice = struct {
    id: []const u8,
    intr_active: u8,
    intr_identify: u8,
    line_control: u8,
    line_status: u8,
    modem_control: u8,
    modem_status: u8,
    scratch: u8,
    baud_divisor: u16,
    in_buf: std.ArrayList(u8),
    out: fs.File.Writer,

    pub fn init(allocator: std.mem.Allocator) SerialDevice {
        return SerialDevice{
            .id = "serial",
            .intr_active = 0,
            .intr_identify = InterruptIdentification,
            .line_control = LineControl,
            .line_status = LineStatus,
            .modem_control = ModemControl,
            .modem_status = ModemStatus,
            .scratch = 0,
            .baud_divisor = BaudDivisor,
            .in_buf = std.ArrayList(u8).init(allocator),
            .out = std.io.getStdOut().writer(),
        };
    }

    pub fn dev(
        self: *@This(),
    ) Device {
        return Device{
            .base = 0x3f8,
            .size = 0x400,
            .ptr = self,
            .vtable = &.{
                .read = read,
                .write = write,
            },
        };
    }

    fn dlab_set(self: *@This()) bool {
        return (self.line_control & LcrDlabBit) != 0;
    }

    fn modem_ctrl_loop(self: *@This()) bool {
        return (self.modem_control & McrLoopBit) != 0;
    }

    fn thr_intr_enabled(self: *@This()) bool {
        return (self.intr_active & IerThrBit) != 0;
    }

    fn add_intr_bit(self: *@This(), bit: u8) void {
        self.intr_identify &= @boolToInt(!@bitCast(bool, @truncate(u1, IirNoneBit)));
        self.intr_identify |= bit;
    }

    fn thr_empty(self: *@This()) void {
        if (self.thr_intr_enabled()) {
            self.add_intr_bit(IirThrBit);
        }
    }

    fn do_write(self: *@This(), offset: u64, base: u8) anyerror!void {
        const off = @intCast(u8, offset);
        switch (off) {
            DlabLow...DlabHigh => {
                if (off == DlabLow and self.dlab_set()) {
                    self.baud_divisor = (self.baud_divisor & 0xff00) | @as(u16, base);
                } else if (off == DlabHigh and self.dlab_set()) {
                    self.baud_divisor = (self.baud_divisor & 0x00ff) | @as(u16, base);
                } else if (off == Data) {
                    if (self.modem_ctrl_loop()) {
                        if (self.in_buf.items.len < LoopSize) {
                            try self.in_buf.append(base);
                        }
                    } else {
                        try self.out.writeAll(&[_]u8{base});
                        self.thr_empty();
                    }
                } else if (off == Ier) {
                    self.intr_active = base & IerFifoBits;
                }
            },
            Lcr => self.line_control = base,
            Mcr => self.modem_control = base,
            Scr => self.scratch = base,
            else => {},
        }
    }

    fn read(ctx: *anyopaque, offset: u64, _: u64, data: []u8) anyerror!void {
        const self = @ptrCast(*SerialDevice, @alignCast(@alignOf(SerialDevice), ctx));
        const off = @intCast(u8, offset);
        data[0] = switch (off) {
            DlabLow...DlabHigh => dlab: {
                if (off == DlabLow and self.dlab_set()) {
                    break :dlab @intCast(u8, self.baud_divisor);
                } else if (off == DlabHigh and self.dlab_set()) {
                    break :dlab @intCast(u8, self.baud_divisor >> 8);
                } else if (off == Data) {
                    if (self.in_buf.items.len <= 1) {
                        self.line_status &= @boolToInt(!@bitCast(bool, @truncate(u1, LsrDataBit)));
                    }
                    _ = self.in_buf.pop();
                } else if (off == Ier) {
                    break :dlab self.intr_identify;
                }
            },
            Lcr => self.line_control,
            Mcr => self.modem_control,
            Msr => self.modem_status,
            Lsr => self.line_status,
            Scr => self.scratch,
            else => 0,
        };
    }
    fn write(ctx: *anyopaque, offset: u64, _: u64, data: []u8) !void {
        const self = @ptrCast(*@This(), @alignCast(@alignOf(@This()), ctx));
        try self.do_write(offset, data[0]);
    }
};
