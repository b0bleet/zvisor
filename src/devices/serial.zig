const std = @import("std");
const io = @import("../io.zig");
const interrupt = @import("../interrupt.zig");
const fs = std.fs;
const stdout = std.io.getStdOut().writer();

const Device = io.Device;

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
const LsrIntAnyBit: u8 = 0x1e;

const IirFifoBits: u8 = 0xc0;
const IirNoneBit: u8 = 0x1;
const IirThrBit: u8 = 0x2;
const IirRecvBit: u8 = 0x4;
const IirRlsiBit: u8 = 0x6;
const IirMsiBit: u8 = 0x00;

const IerRecvBit: u8 = 0x1;
const IerThrBit: u8 = 0x2;
const IerFifoBits: u8 = 0x0f;
const IerRlsiBit: u8 = 0x4;
const IerMsiBit: u8 = 0x8;

const MsrAnyDeltaBit: u8 = 0xf;

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

const LoopSize = 0x40;

pub const SerialDevice = struct {
    id: []const u8,
    intr_enable: u8,
    intr_identify: u8,
    line_control: u8,
    line_status: u8,
    modem_control: u8,
    modem_status: u8,
    scratch: u8,
    baud_divisor: u16,
    in_buf: std.ArrayList(u8),
    out: fs.File.Writer,
    interrupt: *interrupt.InterruptManager,
    irq: u32,
    irq_status: u32,
    m: std.Thread.Mutex = .{},

    pub fn init(allocator: std.mem.Allocator, intr_manager: *interrupt.InterruptManager) SerialDevice {
        return SerialDevice{
            .id = "serial",
            .intr_enable = 0,
            .intr_identify = InterruptIdentification,
            .line_control = LineControl,
            .line_status = LineStatus,
            .modem_control = ModemControl,
            .modem_status = ModemStatus,
            .scratch = 0,
            .baud_divisor = BaudDivisor,
            .in_buf = std.ArrayList(u8).init(allocator),
            .out = std.io.getStdOut().writer(),
            .interrupt = intr_manager,
            .irq = 4,
            .irq_status = 0,
        };
    }

    pub fn dev(
        self: *@This(),
    ) Device {
        return Device{
            .deinit = deinit,
            .base = 0x3f8,
            .size = 0x400,
            .ptr = self,
            .vtable = &.{
                .read = read,
                .write = write,
            },
        };
    }

    pub fn queue_bytes(self: *@This(), bytes: *const []u8) !void {
        self.m.lock();
        defer self.m.unlock();
        if (!self.modem_ctrl_loop()) {
            try self.in_buf.appendSlice(bytes.*);
            try self.recv_data();
        }
        try self.update_irq();
    }

    fn dlab_set(self: *@This()) bool {
        return (self.line_control & LcrDlabBit) != 0;
    }

    fn modem_ctrl_loop(self: *@This()) bool {
        return (self.modem_control & McrLoopBit) != 0;
    }

    fn is_thr_intr_enabled(self: *@This()) bool {
        return (self.intr_enable & IerThrBit) != 0;
    }

    fn is_recv_intr_enabled(self: *@This()) bool {
        return (self.intr_enable & IerRecvBit) != 0;
    }

    fn is_thr_iir_enabled(self: *@This()) bool {
        return (self.intr_identify & IirThrBit != 0);
    }

    fn thr_empty(self: *@This()) !void {
        if (self.is_thr_intr_enabled()) {
            self.mod_intr_id_bit(IirThrBit);
            try self.trigger_interrupt(1);
        }
    }

    fn iir_reset(self: *@This()) void {
        self.intr_identify = InterruptIdentification;
    }

    fn mod_intr_id_bit(self: *@This(), bit: u8) void {
        self.intr_identify &= ~IirNoneBit;
        self.intr_identify |= bit;
    }

    fn clear_intr_bit(self: *@This(), bit: u8) void {
        self.intr_identify &= ~bit;
        if (self.intr_identify == 0x0) {
            self.intr_identify = IirNoneBit;
        }
    }

    fn recv_data(self: *@This()) !void {
        if (self.is_recv_intr_enabled()) {
            self.mod_intr_id_bit(IirRecvBit);
            try self.trigger_interrupt(1);
        }
        self.line_status |= LsrDataBit;
    }

    fn update_irq(self: *@This()) !void {
        if (!self.is_thr_intr_enabled() and self.irq_status != 0) {
            try self.trigger_interrupt(0);
        }
    }

    fn trigger_interrupt(self: *@This(), level: u8) anyerror!void {
        try self.interrupt.trigger(self.irq, level);
        self.irq_status = self.intr_enable;
    }

    fn popFrontOrNull(self: *@This()) ?@TypeOf(self.in_buf.items[0]) {
        if (self.in_buf.items.len == 0) return null;
        const val = self.in_buf.items[0];
        self.in_buf.items = self.in_buf.items[1..];
        return val;
    }

    fn do_write(self: *@This(), off: u8, base: u8) anyerror!void {
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
                            try self.recv_data();
                        }
                    } else {
                        try self.out.writeAll(&[_]u8{base});
                        try self.thr_empty();
                    }
                } else if (off == Ier) {
                    self.intr_enable = base & IerFifoBits;
                }
            },
            Lcr => self.line_control = base,
            Mcr => self.modem_control = base,
            Scr => self.scratch = base,
            else => {},
        }
        try self.update_irq();
    }

    fn read(ctx: *anyopaque, offset: u64, _: u64, data: []u8) anyerror!void {
        const self = @ptrCast(*SerialDevice, @alignCast(@alignOf(SerialDevice), ctx));
        const off = @truncate(u8, offset);

        self.m.lock();
        defer self.m.unlock();

        data[0] = switch (off) {
            DlabLow...DlabHigh => dlab: {
                if (off == DlabLow and self.dlab_set()) {
                    break :dlab @truncate(u8, self.baud_divisor);
                } else if (off == DlabHigh and self.dlab_set()) {
                    break :dlab @truncate(u8, self.baud_divisor >> 8);
                } else if (off == Data) {
                    self.clear_intr_bit(IirRecvBit);
                    if (self.in_buf.items.len <= 1) {
                        self.line_status &= ~LsrDataBit;
                    }
                    break :dlab if (self.popFrontOrNull()) |val| val else 0;
                } else if (off == Ier) {
                    break :dlab self.intr_enable;
                }
            },
            Iir => iirblk: {
                const i = self.intr_identify | IirFifoBits;
                self.iir_reset();
                break :iirblk i;
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

        self.m.lock();
        defer self.m.unlock();

        try self.do_write(@truncate(u8, offset), data[0]);
    }

    pub fn deinit(ctx: *anyopaque) void {
        const self = @ptrCast(*@This(), @alignCast(@alignOf(@This()), ctx));
        self.in_buf.deinit();
    }
};
