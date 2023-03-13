const std = @import("std");
const builtin = @import("builtin");
const os = std.os;
const system = os.system;
const ioctl = system.ioctl;
const errno = system.getErrno;
const assert = std.debug.assert;

const SA = os.SA;
const SIG = os.SIG;
const Sigaction = os.Sigaction;

pub const UtilsError = error{
    IoCtlErr,
};

pub extern fn sigfillset(set: *os.sigset_t) c_int;
pub extern fn __libc_current_sigrtmin() c_int;
pub extern fn __libc_current_sigrtmax() c_int;
const SigHandler = os.Sigaction.handler_fn;

pub fn sigrtmin() u6 {
    return @intCast(u6, __libc_current_sigrtmin());
}

pub fn sigrtmax() u6 {
    return @intCast(u6, __libc_current_sigrtmax());
}

pub fn register_signal(num: u6, comptime handler: os.Sigaction.handler_fn) void {
    var sigact = Sigaction{
        .handler = .{ .handler = handler },
        .mask = os.empty_sigset,
        .flags = SA.SIGINFO,
    };

    if (sigfillset(@ptrCast(*os.sigset_t, &sigact.mask)) != 0) {
        @panic("unable to fill a signal set");
    }

    os.sigaction(num, &sigact, null) catch @panic("unable to set signal action");
}

pub fn send_ioctl_res(fd_: os.fd_t, request: c_ulong, arg: usize) UtilsError!usize {
    const fd = @bitCast(usize, @as(isize, fd_));
    while (true) {
        const rc = os.linux.syscall3(.ioctl, fd, request, arg);
        switch (errno(rc)) {
            .SUCCESS => return rc,
            .INTR => continue,
            else => return UtilsError.IoCtlErr,
        }
    }
    unreachable;
}

pub fn send_ioctl(fd_: os.fd_t, request: c_ulong, arg: usize) UtilsError!void {
    const fd = @bitCast(usize, @as(isize, fd_));
    while (true) {
        const rc = os.linux.syscall3(.ioctl, fd, request, arg);
        switch (errno(rc)) {
            .SUCCESS => return,
            .INTR => continue,
            else => return UtilsError.IoCtlErr,
        }
    }
    unreachable;
}
