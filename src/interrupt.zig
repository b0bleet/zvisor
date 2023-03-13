const vm = @import("zvisor.zig");
const std = @import("std");
const log = std.log.scoped(.interrupt);
const Accel = vm.Accel;

pub const APIC_LVT0 = 0x35;
pub const APIC_LVT1 = 0x36;
pub const APIC_SPIV = 0xf;
pub const APIC_MODE_NMI = 0x4;
pub const APIC_MODE_EXTINT = 0x7;

pub const InterruptManager = struct {
    accelerator: Accel,
    allocator: std.mem.Allocator,
    use_accelerator_apic: bool = true,

    pub fn init(accelerator: *const Accel, allocator: std.mem.Allocator) !*InterruptManager {
        var intr_manager = try allocator.create(InterruptManager);
        intr_manager.* = InterruptManager{ .accelerator = accelerator.*, .allocator = allocator };
        return intr_manager;
    }

    pub fn deinit(self: *@This()) void {
        self.allocator.destroy(self);
    }

    inline fn deliv_mode(reg: u32, mode: u32) u32 {
        return ((reg) & ~@as(u16, 0x700)) | ((mode) << 8);
    }

    pub fn setup_accel_apic(self: *@This()) !bool {
        const accel = self.accelerator.vtable;
        if (accel.apic) |apic| {
            const accel_interrupt = try apic.setup_ioapic(self.accelerator.ptr);
            return accel_interrupt;
        }
        return false;
    }

    pub fn setup_apic(self: *@This()) !void {
        const accelerator_apic = try self.setup_accel_apic();
        if (!accelerator_apic) {
            log.warn("Accelerator based IrqChip isn't supported", .{});
            self.setup_internal_apic();
            self.use_accelerator_apic = false;
        }
        try self.set_lint_pins();
    }

    pub fn set_lint_pins(self: *@This()) !void {
        const vcpu = self.accelerator.vtable;
        if (vcpu.apic) |apic| {
            if (self.use_accelerator_apic) {
                const accelerator = self.accelerator;
                var kapic = try apic.get_klapic(accelerator.ptr);

                apic.set_klapic_reg(accelerator.ptr, &kapic, APIC_SPIV, 0x1ff);

                const lvt0 = apic.get_klapic_reg(accelerator.ptr, &kapic, APIC_LVT0);
                apic.set_klapic_reg(accelerator.ptr, &kapic, APIC_LVT0, deliv_mode(lvt0, APIC_MODE_EXTINT));

                const lvt1 = apic.get_klapic_reg(accelerator.ptr, &kapic, APIC_LVT1);
                apic.set_klapic_reg(accelerator.ptr, &kapic, APIC_LVT1, deliv_mode(lvt1, APIC_MODE_NMI));

                try apic.set_klapic(accelerator.ptr, &kapic);
            }
        } else {
            // Setting LINT pins using the internal APIC controller.
            unreachable;
        }
    }

    pub fn setup_internal_apic(_: *@This()) void {}

    pub fn inject_interrupt(_: *@This(), _: u32, _: u32) void {}

    pub fn trigger(self: *@This(), irq: u32, level: u32) !void {
        if (self.use_accelerator_apic) {
            const vcpu = self.accelerator.vtable;
            try vcpu.inject_interrupt(self.accelerator.ptr, irq, level);
        } else {
            self.inject_interrupt(irq, level);
        }
    }
};
