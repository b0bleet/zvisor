const vm = @import("zvisor.zig");
const std = @import("std");
const Accel = vm.Accel;

pub const APIC_LVT0 = 0x35;
pub const APIC_LVT1 = 0x36;
pub const APIC_SPIV = 0xf;
pub const APIC_MODE_NMI = 0x4;
pub const APIC_MODE_EXTINT = 0x7;

pub const InterruptManager = struct {
    accel: Accel,
    allocator: std.mem.Allocator,

    pub fn init(accelerator: *const Accel, allocator: std.mem.Allocator) !*InterruptManager {
        var intr_manager = try allocator.create(InterruptManager);
        intr_manager.* = InterruptManager{ .accel = accelerator.*, .allocator = allocator };
        return intr_manager;
    }

    pub fn deinit(self: *@This()) void {
        self.allocator.destroy(self);
    }

    pub fn trigger(self: *@This(), irq: u32, level: u32) !void {
        const vcpu = self.accel.vtable;
        try vcpu.inject_interrupt(self.accel.ptr, irq, level);
    }
};

inline fn deliv_mode(reg: u32, mode: u32) u32 {
    return ((reg) & ~@as(u16, 0x700)) | ((mode) << 8);
}

pub fn set_lint(accel: *const Accel) !void {
    const vcpu = accel.vtable;
    var kapic = try vcpu.get_klapic(accel.ptr);
    vcpu.set_klapic_reg(accel.ptr, &kapic, APIC_SPIV, 0x1ff);

    const lvt0 = vcpu.get_klapic_reg(accel.ptr, &kapic, APIC_LVT0);
    vcpu.set_klapic_reg(accel.ptr, &kapic, APIC_LVT0, deliv_mode(lvt0, APIC_MODE_EXTINT));

    const lvt1 = vcpu.get_klapic_reg(accel.ptr, &kapic, APIC_LVT1);
    vcpu.set_klapic_reg(accel.ptr, &kapic, APIC_LVT1, deliv_mode(lvt1, APIC_MODE_NMI));

    try vcpu.set_klapic(accel.ptr, &kapic);
}
