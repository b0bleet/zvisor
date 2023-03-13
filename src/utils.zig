const std = @import("std");
const builtin = @import("builtin");
const os = std.os;
const assert = std.debug.assert;

const OS_Linux = @import("utils/linux.zig");

const ARCH_x86_64 = @import("utils/x86_64.zig");

pub const UtilsError = error{
    IoCtlErr,
};

pub const OS = switch (builtin.target.os.tag) {
    .linux => OS_Linux,
    else => @compileError("unsupported OS for syscall handler"),
};

pub const ARCH = switch (builtin.target.cpu.arch) {
    .x86_64 => ARCH_x86_64,
    else => @compileError("unsupported OS for syscall handler"),
};

pub fn fatal(comptime fmt_string: []const u8, args: anytype) noreturn {
    const stderr = std.io.getStdErr().writer();
    stderr.print("error: " ++ fmt_string ++ "\n", args) catch {};
    os.exit(1);
}

pub fn read_file(
    allocator: std.mem.Allocator,
    file: []const u8,
) anyerror![]u8 {
    var f = try std.fs.openFileAbsolute(file, std.fs.File.OpenFlags{ .mode = .read_only });
    defer f.close();
    const stats = try f.stat();
    return try f.readToEndAlloc(allocator, stats.size);
}

pub fn alloc_mem(size: usize, fd: ?std.fs.File) os.MMapError![]align(std.mem.page_size) u8 {
    const file = if (fd) |_fd| _fd.handle else -1;
    const vm_mem = os.mmap(
        null,
        size,
        os.PROT.READ | os.PROT.WRITE,
        if (fd) |_| os.MAP.SHARED else os.MAP.SHARED | os.MAP.ANONYMOUS,
        file,
        0,
    ) catch |err| switch (err) {
        error.MemoryMappingNotSupported => unreachable,
        error.AccessDenied => unreachable,
        error.PermissionDenied => unreachable,
        else => |e| {
            return e;
        },
    };
    assert(vm_mem.len == size);
    return vm_mem;
}

pub fn get_field(comptime T: type, comptime field: []const u8) type {
    switch (@typeInfo(T)) {
        .Struct => {
            comptime inline for (@typeInfo(T).Struct.fields) |f| {
                if (std.mem.eql(u8, f.name, field)) {
                    return f.type;
                }
            };
        },
        .Union => {
            comptime inline for (@typeInfo(T).Union.fields) |f| {
                if (std.mem.eql(u8, f.name, field)) {
                    return f.type;
                }
            };
        },
        else => {
            @compileError("Unable to handle field: '" ++ @typeName(T) ++ "'");
        },
    }
    @compileError("unable to find field: '" ++ field ++ "' in: '" ++ @typeName(T) ++ "'");
}
