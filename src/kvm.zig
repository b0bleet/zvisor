const std = @import("std");
const builtin = @import("builtin");
const os = std.os;
const c_kvm = @import("root").c_kvm;
const utils = @import("utils.zig");
const io = @import("io.zig");
const zig_vm = @import("zvisor.zig");
const log = std.log.scoped(.kvm);
const fatal = utils.fatal;
const assert = std.debug.assert;

const OS = utils.OS;
const ARCH = utils.ARCH;
const Config = @import("root").Config;

const Vm = zig_vm.Vm;
const Accel = zig_vm.Accel;
const LapicState = zig_vm.LapicState;

const ZvCpuid = zig_vm.ZvCpuid;

// Utils API
const send_ioctl_res = OS.send_ioctl_res;
const send_ioctl = OS.send_ioctl;

// KVM API
const KvmRegs = c_kvm.kvm_regs;
const KvmSregs = c_kvm.kvm_sregs;
const KvmUserSpaceMemoryRegion = c_kvm.kvm_userspace_memory_region;
const KvmCpuidEntry2 = c_kvm.kvm_cpuid_entry2;
const KvmPitConfig = c_kvm.kvm_pit_config;
const KvmLapicState = c_kvm.kvm_lapic_state;

const KVM_GET_SUPPORTED_CPUID = c_kvm.KVM_GET_SUPPORTED_CPUID;
const KVM_CREATE_VM = c_kvm.KVM_CREATE_VM;
const KVM_SET_USER_MEMORY_REGION = c_kvm.KVM_SET_USER_MEMORY_REGION;
const KVM_CREATE_VCPU = c_kvm.KVM_CREATE_VCPU;
const KVM_SET_CPUID2 = c_kvm.KVM_SET_CPUID2;
const KVM_GET_SREGS = c_kvm.KVM_GET_SREGS;
const KVM_SET_SREGS = c_kvm.KVM_SET_SREGS;
const KVM_SET_REGS = c_kvm.KVM_SET_REGS;
const KVM_GET_REGS = c_kvm.KVM_GET_REGS;
const KVM_GET_VCPU_MMAP_SIZE = c_kvm.KVM_GET_VCPU_MMAP_SIZE;
const KVM_RUN = c_kvm.KVM_RUN;
const KVM_MEM_READONLY = c_kvm.KVM_MEM_READONLY;
const KVM_CPUID_SIGNATURE = c_kvm.KVM_CPUID_SIGNATURE;
const KVM_CPUID_FEATURES = c_kvm.KVM_CPUID_FEATURES;
const KVM_CREATE_PIT2 = c_kvm.KVM_CREATE_PIT2;
const KVM_CREATE_IRQCHIP = c_kvm.KVM_CREATE_IRQCHIP;
const KVM_CHECK_EXTENSION = c_kvm.KVM_CHECK_EXTENSION;
const KVM_CAP_GET_TSC_KHZ = c_kvm.KVM_CAP_GET_TSC_KHZ;
const KVM_GET_TSC_KHZ = c_kvm.KVM_GET_TSC_KHZ;
const KVM_SET_TSC_KHZ = c_kvm.KVM_SET_TSC_KHZ;
const KVM_GET_LAPIC = c_kvm.KVM_GET_LAPIC;
const KVM_SET_LAPIC = c_kvm.KVM_SET_LAPIC;
const KVM_IRQ_LINE = c_kvm.KVM_IRQ_LINE;
const KVM_IRQ_LINE_STATUS = c_kvm.KVM_IRQ_LINE_STATUS;
const KVM_CAP_IRQ_INJECT_STATUS = c_kvm.KVM_CAP_IRQ_INJECT_STATUS;
const KVM_IRQCHIP_IOAPIC = c_kvm.KVM_IRQCHIP_IOAPIC;
const KVM_CAP_IRQCHIP = c_kvm.KVM_CAP_IRQCHIP;

// hacky way to call `KVM_GET_IRQCHIP/KVM_SET_IRQCHIP` ioctl command with modified `kvm_irqchip`
const KVM_GET_IRQCHIP = c_kvm._IOWR(c_kvm.KVMIO, @as(c_int, 0x62), KvmIrqChip);
const KVM_SET_IRQCHIP = c_kvm._IOWR(c_kvm.KVMIO, @as(c_int, 0x63), KvmIrqChip);

pub const VmRunErr = error{
    FailIoReq,
    FailMmioReq,
    FailVmRun,
    FailGetRegs,
};

const ZvisorExit = enum {
    Unknown,
    Exception,
    Io,
    HyperCall,
    Debug,
    Hlt,
    Mmio,
    IrqWindowOpen,
    Shutdown,
    FailEntry,
    Intr,
    SetTpr,
    TprAccess,
    S390Access,
    S390Reset,
    Dcr,
    Nmi,
    InternalError,
    Osi,
    PaprHcall,
    S390uControl,
    WatchDog,
    S390Tsch,
    Epr,
    SystemEvent,
    S390Stsi,
    IoApicEoi,
    Hyperv,
    ArmNisv,
    X86Rdmsr,
    X86Wrmsr,
    DirtyRingFull,
    ApResetHold,
    x86BusLock,
    Xen,
    RiscvSbi,
    RiscvCsr,
    Notify,
};

const KvmPicState = extern struct {
    last_irr: u8, // edge detection
    irr: u8, // interrupt request register
    imr: u8, // interrupt mask register
    isr: u8, // interrupt service register
    priority_add: u8, // highest irq priority
    irq_base: u8,
    read_reg_select: u8,
    poll: u8,
    special_mask: u8,
    init_state: u8,
    auto_eoi: u8,
    rotate_on_auto_eoi: u8,
    special_fully_nested_mode: u8,
    init4: u8, // true if 4 byte init
    elcr: u8, // PIIX edge/trigger selection
    elcr_mask: u8,
};

const KvmIoApicState = extern struct {
    const KvmIoApicNumPins = 24;

    base_address: u64,
    ioregsel: u32,
    id: u32,
    irr: u32,
    pad: u32,
    redirtbl: [KvmIoApicNumPins]u64,
};

const KvmIrqChip = extern struct {
    chip_id: u32,
    pad: u32,
    chip: extern union {
        dummy: [512]u8,
        pic: KvmPicState,
        ioapic: KvmIoApicState,
    },
};

pub const KvmIrqLevel = extern struct {
    u_flds: extern union {
        irq: u32,
        level: u32,
    },
    level: u32,
};

// KVM run context structure
pub const KvmRun = extern struct {
    request_interrupt_window: u8,
    immediate_exit: u8,
    padding1: [6]u8,
    exit_reason: u32,
    ready_for_interrupt_injection: u8,
    if_flag: u8,
    flags: u16,
    cr8: u64,
    apic_base: u64,
    u_flds: extern union {
        hw: extern struct {
            hardware_exit_reason: u64,
        },
        fail_entry: extern struct {
            hardware_entry_failure_reason: u64,
            cpu: u32,
        },
        ex: extern struct {
            exception: u32,
            error_code: u32,
        },
        io: extern struct {
            direction: u8,
            size: u8,
            port: u16,
            count: u32,
            data_offset: u64,
        },
        debug: extern struct {
            arch: c_kvm.kvm_debug_exit_arch,
        },
        mmio: extern struct {
            phys_addr: u64,
            data: [8]u8,
            len: u32,
            is_write: u8,
        },
        hypercall: extern struct {
            nr: u64,
            args: [6]u64,
            ret: u64,
            longmode: u32,
            pad: u32,
        },
        tpr_access: extern struct {
            rip: u64,
            is_write: u32,
            pad: u32,
        },
        s390_sieic: extern struct {
            icptcode: u8,
            ipa: u16,
            ipb: u32,
        },
        s390_reset_flags: u64,
        s390_ucontrol: extern struct {
            trans_exc_code: u64,
            pgm_code: u32,
        },
        dcr: extern struct {
            dcrn: u32,
            data: u32,
            is_write: u8,
        },
        internal: extern struct {
            suberror: u32,
            ndata: u32,
            data: [16]u64,
        },
        osi: extern struct {
            gprs: [32]u64,
        },
        papr_hcall: extern struct {
            nr: u64,
            ret: u64,
            args: [9]u64,
        },
        s390_tsch: extern struct {
            subchannel_id: u16,
            subchannel_nr: u16,
            io_int_parm: u32,
            io_int_word: u32,
            ipb: u32,
            dequeued: u8,
        },
        epr: extern struct {
            epr: u32,
        },
        system_event: extern struct {
            type: u32,
            flags: u64,
        },
        s390_stsi: extern struct {
            addr: u64,
            ar: u8,
            reserved: u8,
            fc: u8,
            sel1: u8,
            sel2: u16,
        },
        eoi: extern struct {
            vector: u8,
        },
        hyperv: c_kvm.kvm_hyperv_exit,
        arm_nisv: extern struct {
            esr_iss: u64,
            fault_ipa: u64,
        },
        msr: extern struct {
            @"error": u8,
            pad: [7]u8,
            reason: u32,
            index: u32,
            data: u64,
        },
        padding: [256]u8,
    },
    kvm_valid_regs: u64,
    kvm_dirty_regs: u64,
    s: extern union {
        regs: c_kvm.kvm_sync_regs,
        padding: [2048]u8,
    },
};

// VM context during BIOS initialization stage
const BiosCtx = struct {
    const VM_FW_CS_BASE = 0xffff0000;
    const VM_FW_CS_SEL = 0xf000;
    const VM_FW_IP = 0xfff0;
    const VM_FW_SP = 0x7c00;
    const VM_FW_EFLAGS = (1 << 1);
};

// VMM Error
const VmmError = error{
    VmmCreateErr,
    VmmMemErr,
};

const E820Types = enum {
    e820_ram,
    e820_reserved,
    e820_acpi,
    e820_nvs,
    e820_unusable,
};

const KvmMem = struct {
    slot: u32,
    mem: usize,
    phys_addr: usize,
    size: u64,
    flags: u32,
};

const MsrEntry = struct {
    index: u32,
    data: u64,
};

const VcpuState = struct {
    cpu_id: u32,
    msrs: std.ArrayList(MsrEntry),
    vcpufd: os.fd_t,
};

const KvmCpuid = struct {
    nent: u32,
    padding: u32 = undefined,
    entries: void = undefined, // should be zero-sized
};

const MaxCpuidEntries = 100;
const MaxE820Entries = 1;

const kvm_io_type = utils.get_field(utils.get_field(KvmRun, "u_flds"), "io");

pub const Kvm = struct {
    const Self = @This();

    vm: *Vm = undefined,
    kvmfd: os.fd_t,
    vmfd: c_int,
    vcpu_run: []align(std.mem.page_size) u8,
    vcpufd: os.fd_t,
    allocator: std.mem.Allocator,
    irq_ioctl: u32 = KVM_IRQ_LINE,
    vcpu_state: std.ArrayList(VcpuState),

    pub fn init(allocator: std.mem.Allocator, vm_ctx: *Vm, cpus: u8) anyerror!Kvm {
        const flags: u32 = os.O.CLOEXEC | os.O.RDWR | os.O.DSYNC;
        var mode: os.mode_t = 0;
        const fd = try os.open("/dev/kvm", flags, mode);
        errdefer os.close(fd);

        return std.mem.zeroInit(Kvm, .{
            .allocator = allocator,
            .kvmfd = fd,
            .vm = vm_ctx,
            .vcpu_state = try std.ArrayList(VcpuState).initCapacity(allocator, cpus),
        });
    }

    pub fn deinit(self: *Self) void {
        os.close(self.kvmfd);
        os.munmap(self.vcpu_run);

        // iterate over vcpus and deallocate msr entries
        if (self.vcpu_state.items.len != 0) {
            for (self.vcpu_state.items) |vcpu| {
                vcpu.msrs.deinit();
            }
        }
        self.vcpu_state.deinit();
    }

    fn create_vm(self: *Self) utils.UtilsError!os.fd_t {
        const fd = try send_ioctl_res(self.kvmfd, KVM_CREATE_VM, @intCast(c_ulong, 0));
        return @intCast(os.fd_t, fd);
    }

    fn create_vcpu(self: *Self) utils.UtilsError!os.fd_t {
        const fd = try send_ioctl_res(self.vmfd, KVM_CREATE_VCPU, @intCast(c_ulong, 0));
        return @intCast(os.fd_t, fd);
    }

    fn add_mem_slot(self: *Self, kmem: KvmMem) anyerror!void {
        var region: KvmUserSpaceMemoryRegion = .{
            .slot = kmem.slot,
            .guest_phys_addr = kmem.phys_addr,
            .memory_size = kmem.size,
            .flags = kmem.flags,
            .userspace_addr = kmem.mem,
        };
        try send_ioctl(self.vmfd, KVM_SET_USER_MEMORY_REGION, @ptrToInt(&region));
    }

    fn get_cpuid(self: *Self, max_entries: u32) anyerror!?[]align(@alignOf(KvmCpuid)) u8 {
        assert(max_entries > 0);

        const calc_entries = @sizeOf(KvmCpuid) + (max_entries * @sizeOf(KvmCpuidEntry2));
        const cpuid = try self.allocator.alignedAlloc(u8, @alignOf(KvmCpuid), calc_entries);
        const res = @ptrCast(*KvmCpuid, cpuid.ptr);
        res.* = .{ .nent = max_entries };
        try send_ioctl(self.kvmfd, KVM_GET_SUPPORTED_CPUID, @ptrToInt(cpuid.ptr));
        return cpuid;
    }

    fn patch_kvm_cpuid(_: *Self, cpuids: std.ArrayList(zig_vm.ZvCpuid.Cpuid), kvm_cpuids: []KvmCpuidEntry2) bool {
        assert(kvm_cpuids.len > 0);
        var found = false;

        for (cpuids.items) |cpuid| {
            for (kvm_cpuids) |*entry| {
                if (cpuid.Function == entry.function and
                    (cpuid.Index == null or cpuid.Index == entry.index))
                {
                    if (cpuid.SetBits) {
                        if (cpuid.Eax) |Eax| entry.eax |= Eax;
                        if (cpuid.Ebx) |Ebx| entry.ebx |= Ebx;
                        if (cpuid.Ecx) |Ecx| entry.ecx |= Ecx;
                        if (cpuid.Edx) |Edx| entry.edx |= Edx;
                    } else {
                        if (cpuid.Eax) |Eax| entry.eax = Eax;
                        if (cpuid.Ebx) |Ebx| entry.ebx = Ebx;
                        if (cpuid.Ecx) |Ecx| entry.ecx = Ecx;
                        if (cpuid.Edx) |Edx| entry.edx = Edx;
                    }
                    found = true;
                }
            }
        }
        return found;
    }

    fn set_cpuids(ctx: *anyopaque, cpuids: std.ArrayList(zig_vm.ZvCpuid.Cpuid)) anyerror!void {
        const self = @ptrCast(*Kvm, @alignCast(@alignOf(Kvm), ctx));
        var max_entries: u32 = 1;
        blk: while (try self.get_cpuid(max_entries)) |cpuid| {
            var cpuid_ptr = @ptrCast(*KvmCpuid, cpuid.ptr);
            if (cpuid_ptr.nent >= max_entries) {
                self.allocator.free(cpuid);
                max_entries *= 2;
            } else {
                if (cpuid_ptr.nent == 0) break :blk;

                var kvm_cpuids = @ptrCast(
                    [*]KvmCpuidEntry2,
                    @alignCast(@alignOf(*KvmCpuidEntry2), &cpuid_ptr.entries),
                )[0..cpuid_ptr.nent];

                if (cpuids.items.len > 0) {
                    if (!self.patch_kvm_cpuid(cpuids, kvm_cpuids)) {
                        log.warn("unable to find cpuid entry to patch\n", .{});
                    }
                }

                try send_ioctl(self.vcpufd, KVM_SET_CPUID2, @ptrToInt(cpuid.ptr));
                self.allocator.free(cpuid);
                break :blk;
            }
        }
    }

    fn check_kvm_ext(self: *Self, ext: u32) bool {
        send_ioctl(self.kvmfd, KVM_CHECK_EXTENSION, ext) catch |err| switch (err) {
            error.IoCtlErr => return false,
            else => unreachable,
        };
        return true;
    }

    fn init_fw_regs(self: *Self) anyerror!void {
        var sregs = std.mem.zeroes(KvmSregs);
        try send_ioctl(self.vcpufd, KVM_GET_SREGS, @ptrToInt(&sregs));
        sregs.cs.base = BiosCtx.VM_FW_CS_BASE;
        sregs.cs.selector = BiosCtx.VM_FW_CS_SEL;
        try send_ioctl(self.vcpufd, KVM_SET_SREGS, @ptrToInt(&sregs));

        var regs = std.mem.zeroInit(KvmRegs, .{
            .rip = BiosCtx.VM_FW_IP,
            .rsp = BiosCtx.VM_FW_SP,
            .rflags = BiosCtx.VM_FW_EFLAGS,
        });
        try send_ioctl(self.vcpufd, KVM_SET_REGS, @ptrToInt(&regs));
    }

    fn setup_linux_boot(self: *Self, config: *const Config) anyerror!void {
        const e820map = extern struct {
            addr: u64 align(1),
            size: u64 align(1),
            type: u32 align(1),
        };

        const boot_config = struct {
            cmdline_size: u32,
            initrd_size: u32,
            kernel_size: u32,
            vmlinuz_size: u32,
            setup_size: u32,
            cpus_count: u32,

            setup_addr: u32,
            cmdline_addr: u32,
            kernel_addr: u32,
            initrd_addr: u32,
            mem_map: [MaxE820Entries]e820map,
        };
        comptime assert(@sizeOf(boot_config) <= 0x10000);

        const initrd = if (config.initrd) |filename| try utils.read_file(self.allocator, filename) else null;
        const kernel = try utils.read_file(self.allocator, config.kernel);
        defer self.allocator.free(kernel);

        const cmdline = config.cmdline;

        const linux_config_phys: u18 = 0x30000;
        var cmdline_size: u32 = if (cmdline) |cmd| @intCast(u32, (cmd.len + 16) & ~@as(u8, 15)) else 0;

        var header: [8192]u8 = undefined;
        var kernel_size = @intCast(u32, kernel.len);
        @memcpy(@ptrCast([*]u8, &header), kernel.ptr, @min(header.len, kernel_size));
        if (std.mem.readIntLittle(u32, &header[0x202]) != 0x53726448) {
            fatal("ZigVisor does not support multiboot kernel loading\n", .{});
        }
        const protocol: u16 = std.mem.readIntLittle(u16, &header[0x206]);

        var cmdline_addr: u32 = undefined;
        var real_addr: u32 = undefined;
        var prot_addr: u32 = undefined;
        if (protocol < 0x200 or !((std.mem.readIntLittle(u8, &header[0x211]) & 0x1) == 0x1)) {
            real_addr = 0x90000;
            cmdline_addr = 0x9a000 - cmdline_size;
            prot_addr = 0x10000;
        } else if (protocol < 0x202) {
            real_addr = 0x90000;
            cmdline_addr = 0x9a000 - cmdline_size;
            prot_addr = 0x100000;
        } else {
            real_addr = 0x10000;
            cmdline_addr = 0x20000;
            prot_addr = 0x100000;
        }

        var initrd_max: u32 = undefined;
        if (protocol >= 0x203) {
            initrd_max = std.mem.readIntLittle(u32, &header[0x22c]);
        } else {
            initrd_max = 0x37ffffff;
        }

        const lowmem = @intCast(u32, self.vm.vm_mem_size);
        if (initrd_max >= lowmem) {
            initrd_max = lowmem - 1;
        }

        assert(linux_config_phys < self.vm.vm_mem_size);
        const config_area = @intToPtr(*boot_config, @ptrToInt(self.vm.vm_mem_ptr.ptr) + linux_config_phys);

        assert(cmdline_addr < self.vm.vm_mem_size);
        if (cmdline) |cmd| {
            const cmdline_area = @intToPtr([*]u8, @ptrToInt(self.vm.vm_mem_ptr.ptr) + cmdline_addr);
            @memcpy(cmdline_area, cmd.ptr, cmd.len);
            if (cmdline_size > cmd.len) {
                @memset(@intToPtr([*]u8, @ptrToInt(cmdline_area) + cmd.len), 0x0, cmdline_size - cmd.len);
            }
            config_area.cmdline_size = @intCast(u32, cmd.len + 1);
        }

        config_area.initrd_size = 0;
        config_area.cmdline_addr = cmdline_addr;

        if (protocol >= 0x202) {
            std.mem.writeIntLittle(usize, &header[0x228], cmdline_addr);
        } else {
            std.mem.writeIntLittle(u16, &header[0x20], 0xa33f);
            std.mem.writeIntLittle(u16, &header[0x22], @intCast(u16, cmdline_addr - real_addr));
        }

        if (protocol >= 0x200) {
            std.mem.writeIntLittle(u8, &header[0x210], 0xB0);
        }

        if (protocol >= 0x201) {
            var can_use_heap = std.mem.readIntLittle(u8, &header[0x211]);
            can_use_heap |= 0x80;
            std.mem.writeIntLittle(u8, &header[0x211], can_use_heap);
            std.mem.writeIntLittle(u16, &header[0x224], @intCast(u16, cmdline_addr - real_addr - 0x200));
        }

        if (initrd) |initrd_data| {
            const initrd_size: u32 = @intCast(u32, initrd_data.len);
            if (initrd_size >= initrd_max) {
                @panic("initrd file size is too large\n");
            }

            const initrd_addr = (initrd_max - initrd_size) & ~@as(u32, 4095);
            assert(initrd_addr < self.vm.vm_mem_size);
            config_area.initrd_size = initrd_size;
            config_area.initrd_addr = initrd_addr;
            const initrd_area = @intToPtr([*]u8, @ptrToInt(self.vm.vm_mem_ptr.ptr) + initrd_addr);
            @memcpy(initrd_area, initrd_data.ptr, initrd_size);

            std.mem.writeIntLittle(u32, &header[0x218], initrd_addr);
            std.mem.writeIntLittle(u32, &header[0x21c], initrd_size);
        }

        var setup_size: u32 = std.mem.readIntLittle(u8, &header[0x1f1]);
        if (setup_size == 0) {
            setup_size = 4;
        }
        setup_size = (setup_size + 1) * 512;
        assert(setup_size < kernel_size);
        kernel_size = kernel_size - setup_size;
        assert(real_addr < self.vm.vm_mem_size);
        const setup_area = @intToPtr([*]u8, @ptrToInt(self.vm.vm_mem_ptr.ptr) + real_addr);
        @memcpy(setup_area, kernel.ptr, setup_size);

        assert(prot_addr < self.vm.vm_mem_size);
        const kernel_area = @intToPtr([*]u8, @ptrToInt(self.vm.vm_mem_ptr.ptr) + prot_addr);
        assert(kernel_size < self.vm.vm_mem_size);
        @memcpy(kernel_area, @intToPtr([*]u8, (@ptrToInt(kernel.ptr) + setup_size)), kernel_size);

        // e820 memory mapping initialization
        config_area.mem_map[0] = .{
            .addr = 0,
            .size = self.vm.vm_mem_size,
            .type = @enumToInt(E820Types.e820_reserved),
        };

        config_area.cpus_count = @intCast(u32, self.vcpu_state.items.len);
        config_area.kernel_addr = prot_addr;
        config_area.kernel_size = kernel_size;
        config_area.setup_size = setup_size;
        config_area.setup_addr = real_addr;
    }

    fn setup_vcpu_mem(self: *Self, vcpufd: i32) ![]align(std.mem.page_size) u8 {
        const size = try send_ioctl_res(self.kvmfd, KVM_GET_VCPU_MMAP_SIZE, @intCast(c_ulong, 0));
        const mmap = os.mmap(
            null,
            size,
            os.PROT.READ | os.PROT.WRITE,
            os.MAP.SHARED,
            vcpufd,
            0,
        ) catch |err| switch (err) {
            error.MemoryMappingNotSupported => unreachable,
            error.AccessDenied => unreachable,
            error.PermissionDenied => unreachable,
            else => |e| {
                return e;
            },
        };
        assert(mmap.len == size);
        errdefer os.munmap(mmap);
        return mmap;
    }

    pub fn get_regs(self: *Self) !KvmRegs {
        var regs: KvmRegs = undefined;
        try send_ioctl(self.vcpufd, KVM_GET_REGS, @ptrToInt(&regs));
        return regs;
    }

    pub fn run_vm(self: *Self) VmRunErr!void {
        vm_run: while (true) {
            send_ioctl(self.vcpufd, KVM_RUN, 0) catch return error.FailVmRun;
            const run = @ptrCast(*KvmRun, @alignCast(@alignOf(KvmRun), &self.vcpu_run[0]));
            const exit_reason = run.exit_reason;
            var regs = self.get_regs() catch return error.FailGetRegs;
            const zv_run = @ptrCast(*KvmRun, @alignCast(@alignOf(KvmRun), run));
            switch (@intToEnum(ZvisorExit, exit_reason)) {
                .Hlt => {
                    log.warn("HLT instruction executed {x}\n", .{regs.rip});
                    break :vm_run;
                },
                .Io => exit_io: {
                    const io_data = @intToPtr([*]u8, @ptrToInt(zv_run) + zv_run.u_flds.io.data_offset);
                    self.vm.dev_manager.handle_dev_req(
                        io.IoDevType.Pmmio,
                        @intToEnum(io.IoReqType, zv_run.u_flds.io.direction),
                        zv_run.u_flds.io.port,
                        io_data,
                        (zv_run.u_flds.io.size * zv_run.u_flds.io.count),
                    ) catch return error.FailIoReq;
                    break :exit_io;
                },
                .Mmio => {
                    self.vm.dev_manager.handle_dev_req(
                        io.IoDevType.Mmio,
                        @intToEnum(io.IoReqType, zv_run.u_flds.mmio.is_write),
                        zv_run.u_flds.mmio.phys_addr,
                        &zv_run.u_flds.mmio.data,
                        zv_run.u_flds.mmio.len,
                    ) catch return error.FailMmioReq;
                },
                .Shutdown => {},
                else => {
                    log.warn("Unknown exit reason {d} {x}\n", .{ exit_reason, regs.rip });
                    unreachable;
                },
            }
        }
    }

    fn inject_interrupt(ctx: *anyopaque, irq: u32, level: u32) anyerror!void {
        const self = @ptrCast(*Kvm, @alignCast(@alignOf(Kvm), ctx));
        var event = std.mem.zeroes(KvmIrqLevel);
        event.u_flds.irq = irq;
        event.level = level;
        try send_ioctl(self.vmfd, self.irq_ioctl, @ptrToInt(&event));
    }

    fn setup_kvm_interrupt(self: *Self) anyerror!void {
        // Create IRQ device to emulate Interrupt Controller
        // qBoot initializes APIC in the MP table that's why
        // APIC should be emulated in the Zvisor
        try send_ioctl(self.vmfd, KVM_CREATE_IRQCHIP, 0);

        // Initialize in-kernel PIT device emulation
        const pit = std.mem.zeroes(KvmPitConfig);
        try send_ioctl(self.vmfd, KVM_CREATE_PIT2, @ptrToInt(&pit));
    }

    fn setup_ioapic(ctx: *anyopaque) !bool {
        const self = @ptrCast(*Kvm, @alignCast(@alignOf(Kvm), ctx));
        if (self.check_kvm_ext(KVM_CAP_IRQCHIP)) {
            const ioapic = try self.get_irqchip(KVM_IRQCHIP_IOAPIC);
            try self.set_irqchip(&ioapic);
            return true;
        }

        return false;
    }

    fn get_klapic_reg(_: *anyopaque, lapic_state: *LapicState, reg: u32) u32 {
        return std.mem.readIntLittle(u32, @intToPtr(
            *u8,
            (@ptrToInt(&lapic_state.kvm_lapic.regs) + @as(u32, reg << 4)),
        ));
    }

    fn set_klapic_reg(_: *anyopaque, lapic_state: *LapicState, reg: u32, val: u32) void {
        std.mem.writeIntLittle(
            u32,
            @intToPtr(*u8, (@ptrToInt(&lapic_state.kvm_lapic.regs) + @as(u32, reg << 4))),
            val,
        );
    }

    fn set_klapic(ctx: *anyopaque, lapic_state: *LapicState) anyerror!void {
        const self = @ptrCast(*Kvm, @alignCast(@alignOf(Kvm), ctx));
        try send_ioctl(self.vcpufd, KVM_SET_LAPIC, @ptrToInt(&lapic_state.kvm_lapic));
    }

    fn set_irqchip(self: *Self, chip: *const KvmIrqChip) !void {
        try send_ioctl(self.vmfd, KVM_SET_IRQCHIP, @ptrToInt(chip));
    }

    fn get_irqchip(self: *Self, irqchip: u32) !KvmIrqChip {
        var chip = std.mem.zeroInit(KvmIrqChip, .{ .chip_id = irqchip });
        try send_ioctl(self.vmfd, KVM_GET_IRQCHIP, @ptrToInt(&chip));
        return chip;
    }

    pub fn get_klapic(ctx: *anyopaque) !LapicState {
        const self = @ptrCast(*Kvm, @alignCast(@alignOf(Kvm), ctx));
        var lapic_state = LapicState{ .kvm_lapic = std.mem.zeroes(KvmLapicState) };
        try send_ioctl(self.vcpufd, KVM_GET_LAPIC, @ptrToInt(&lapic_state.kvm_lapic));
        return lapic_state;
    }

    pub fn get_accel(self: *Self) Accel {
        return Accel{
            .ptr = self,
            .vtable = &.{
                .apic = .{
                    .get_klapic = get_klapic,
                    .get_klapic_reg = get_klapic_reg,
                    .set_klapic_reg = set_klapic_reg,
                    .set_klapic = set_klapic,
                    .setup_ioapic = setup_ioapic,
                },
                .set_cpuids = set_cpuids,
                .inject_interrupt = inject_interrupt,
            },
        };
    }

    pub fn setup_vm(
        self: *Self,
        allocator: std.mem.Allocator,
        config: *const Config,
    ) anyerror!void {
        self.vmfd = try self.create_vm();

        self.add_mem_slot(.{
            .slot = 0,
            .flags = 0,
            .size = self.vm.vm_mem_size,
            .phys_addr = 0x0,
            .mem = @ptrToInt(self.vm.vm_mem_ptr.ptr),
        }) catch |err| fatal("unable to add memory slot for vm: {}\n", .{err});

        self.add_mem_slot(.{
            .slot = 1,
            .flags = KVM_MEM_READONLY,
            .size = self.vm.fw_mem_size,
            .phys_addr = 0xffff0000,
            .mem = @ptrToInt(self.vm.vm_mem_ptr.ptr) + self.vm.fw_phys_mem_area,
        }) catch |err| fatal("unable to add memory slot for firmware: {}\n", .{err});

        if (self.check_kvm_ext(KVM_CAP_IRQ_INJECT_STATUS)) {
            self.irq_ioctl = KVM_IRQ_LINE_STATUS;
        }

        // Create an in-kernel IRQ chip to support emulation of IOAPIC, PIC, and etc.
        // The KVM_CREATE_IRQCHIP ioctl command initializes and configures
        // PIC and I/O APIC to provide emulation of an interrupt controller.
        self.setup_kvm_interrupt() catch |err| fatal("unable to initialize interrupt controller in accelerator: {}\n", .{err});

        self.vcpufd = self.create_vcpu() catch |err| fatal("unable to create vcpu in accelerator: {}\n", .{err});
        const last_vcpu_id = if (self.vcpu_state.getLastOrNull()) |vcpu| vcpu.cpu_id + 1 else 1;
        try self.vcpu_state.append(VcpuState{
            .cpu_id = last_vcpu_id,
            .msrs = std.ArrayList(MsrEntry).init(allocator),
            .vcpufd = self.vcpufd,
        });

        self.vcpu_run = self.setup_vcpu_mem(self.vcpufd) catch |err| fatal("unable to create memory for vcpu: {}\n", .{err});

        try self.setup_linux_boot(config);
        try self.init_fw_regs();
    }
};
