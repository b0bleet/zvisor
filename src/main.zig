const std = @import("std");
const kvm = @import("kvm.zig");
const vm = @import("zvisor.zig");
const utils = @import("utils.zig");
const fatal = utils.fatal;
const eql = std.mem.eql;
const heap = std.heap;
const Vm = vm.Vm;

const version = "0.1.0-dev";
const version_str = std.fmt.comptimePrint("zvisor {s} b0bleet", .{version});

const help =
    \\Usage: zvisor [options]
    \\
    \\-f, --firmware    Firmware file 
    \\-k, --kernel      Kernel file 
    \\-i, --initrd      Initrd file 
    \\-v, --version     Show version information and exit
    \\-h, --help        Display this help and exit
;

const Config = struct {
    help: bool = false,
    version: bool = false,
    fw_empty: bool = true,
    firmware: []u8 = undefined,
    kernel_empty: bool = true,
    kernel: []u8 = undefined,
    initrd: ?[]u8 = undefined,
    cmdline: ?[]u8 = null,
    err: bool = false,
    err_str: []u8 = undefined,
};

fn parseArgs(allocator: std.mem.Allocator, args: []const []const u8) !Config {
    var config: Config = .{};

    var skip = false;
    for (args[1..], 0..) |arg, i| {
        if (skip) {
            skip = false;
            continue;
        }

        const index = i + 1;
        if (eql(u8, arg, "-h") or eql(u8, arg, "--help")) {
            config.help = true;
            return config;
        } else if (eql(u8, arg, "-v") or eql(u8, arg, "--version")) {
            config.version = true;
            return config;
        } else if (eql(u8, arg, "-f") or eql(u8, arg, "--firmware")) {
            if (index + 1 > args.len - 1) {
                config.err = true;
                config.err_str = try std.fmt.allocPrint(
                    allocator,
                    "zvisor: option '{s}' requires an argument\n{s}",
                    .{ arg, help },
                );
                return config;
            }

            config.firmware = try allocator.alloc(u8, args[index + 1].len);
            std.mem.copy(u8, config.firmware, args[index + 1]);
            config.fw_empty = false;
            skip = true;
        } else if (eql(u8, arg, "-k") or eql(u8, arg, "--kernel")) {
            if (index + 1 > args.len - 1) {
                config.err = true;
                config.err_str = try std.fmt.allocPrint(
                    allocator,
                    "zvisor: option '{s}' requires an argument\n{s}",
                    .{ arg, help },
                );
                return config;
            }

            config.kernel = try allocator.alloc(u8, args[index + 1].len);
            std.mem.copy(u8, config.kernel, args[index + 1]);
            config.kernel_empty = false;
            skip = true;
        } else if (eql(u8, arg, "-i") or eql(u8, arg, "--initrd")) {
            if (index + 1 > args.len - 1) {
                config.err = true;
                config.err_str = try std.fmt.allocPrint(
                    allocator,
                    "zvisor: option '{s}' requires an argument\n{s}",
                    .{ arg, help },
                );
                return config;
            }

            config.initrd = try allocator.alloc(u8, args[index + 1].len);
            std.mem.copy(u8, config.initrd.?, args[index + 1]);
            skip = true;
        } else if (eql(u8, arg, "-c") or eql(u8, arg, "--cmdline")) {
            if (index + 1 > args.len - 1) {
                config.err = true;
                config.err_str = try std.fmt.allocPrint(
                    allocator,
                    "zvisor: option '{s}' requires an argument\n{s}",
                    .{ arg, help },
                );
                return config;
            }

            config.cmdline = try allocator.alloc(u8, args[index + 1].len);
            std.mem.copy(u8, config.cmdline.?, args[index + 1]);
            skip = true;
        } else {
            config.err = true;
            config.err_str = try std.fmt.allocPrint(
                allocator,
                "zvisor: unrecognized option '{s}'\n{s}",
                .{ arg, help },
            );
            return config;
        }
    }

    return config;
}

pub fn main() anyerror!void {
    var arena = heap.ArenaAllocator.init(heap.page_allocator);
    defer arena.deinit();

    const stdout = std.io.getStdOut().writer();
    const stderr = std.io.getStdErr().writer();
    const allocator = arena.allocator();

    const args = try std.process.argsAlloc(allocator);
    const config = try parseArgs(allocator, args);

    if (config.err) {
        try stderr.print("{s}\n", .{config.err_str});
        std.process.exit(2);
    } else if (config.help) {
        try stdout.print("{s}\n", .{help});
        std.process.exit(0);
    } else if (config.version) {
        try stdout.print("{s}\n", .{version_str});
        std.process.exit(0);
    } else if (config.fw_empty) {
        try stdout.print("No loadable firmware file specified\n", .{});
        std.process.exit(2);
    } else if (config.kernel_empty) {
        try stdout.print("No loadable kernel file specified\n", .{});
        std.process.exit(2);
    }

    // Setup Linux based VM context and run that on the VMM
    var vm_ctx = Vm{};
    vm_ctx.init(allocator, config.firmware) catch |err| switch (err) {
        error.FileNotFound => {
            fatal("The specified firmware file could not be found.\n", .{});
        },
        else => fatal("unable to initialize vm context: {}", .{err}),
    };
    defer vm_ctx.deinit();

    // Initialize VM accelerator
    // At the moment KVM will be used by default
    var kvm_ctx = kvm.Kvm{ .allocator = allocator };
    // Initialize KVM context
    kvm_ctx.init(&vm_ctx) catch |err| {
        fatal("unable to initialize kvm context: {}", .{err});
    };
    defer kvm_ctx.deinit();
    // Initialize VM setup that depends on OS (linux, win32, bsd)
    kvm_ctx.vm_setup(allocator, config.kernel, config.initrd, config.cmdline) catch |err| {
        fatal("unable to setup accelerator: {}", .{err});
    };
    _ = try kvm_ctx.run_vm();
}

test "simple test" {}
