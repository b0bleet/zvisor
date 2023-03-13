const std = @import("std");
const builtin = @import("builtin");
const utils = @import("utils.zig");
const os = std.os;
const system = os.system;
const errno = system.getErrno;
const serial = @import("devices/serial.zig");

const SerialDevice = serial.SerialDevice;

pub const ConsoleMode = enum {
    Tty,
    Pty,
};

const EpollMode = enum {
    File,
    Unknown,
};

pub const ConsoleController = struct {
    const Self = @This();

    serial: *SerialDevice,
    epollfd: i32,
    mode: i32,
    handle: std.Thread = undefined,

    pub fn init(mode: ConsoleMode, serial_dev: *SerialDevice) !?Self {
        const file_mode = switch (mode) {
            .Tty => tty_blk: {
                const stdin_handle = std.io.getStdIn().handle;
                if (os.isatty(stdin_handle)) {
                    const dup_stdin = try os.dup(stdin_handle);
                    var flags = try os.fcntl(dup_stdin, os.F.GETFL, 0);
                    flags |= os.O.NONBLOCK;
                    _ = try os.fcntl(dup_stdin, os.F.SETFL, flags);

                    break :tty_blk dup_stdin;
                }
                return null;
            },
            else => @panic("unsupported file mode for console device"),
        };

        switch (builtin.os.tag) {
            .linux => {
                const epollfd = try os.epoll_create1(os.linux.EPOLL.CLOEXEC);
                errdefer os.close(epollfd);

                var eventfd_event = os.linux.epoll_event{
                    .events = os.linux.EPOLL.IN,
                    .data = .{ .ptr = @enumToInt(EpollMode.File) },
                };

                try os.epoll_ctl(
                    epollfd,
                    os.linux.EPOLL.CTL_ADD,
                    file_mode,
                    &eventfd_event,
                );

                return Self{
                    .serial = serial_dev,
                    .epollfd = epollfd,
                    .mode = file_mode,
                };
            },
            else => @compileError("unsupported Os"),
        }
        return null;
    }

    pub fn start_thread(self: *Self) anyerror!void {
        self.handle = try std.Thread.spawn(.{}, thread, .{ self.epollfd, self.mode, self.serial });
    }

    fn thread(epollfd: i32, polledfd: i32, serial_dev: *SerialDevice) !void {
        const EpollEventsCount: usize = 3;
        const MaxBufBytes: usize = 64;
        while (true) {
            switch (builtin.os.tag) {
                .linux => {
                    var events: [EpollEventsCount]os.linux.epoll_event = undefined;

                    const counts = os.epoll_wait(epollfd, events[0..], -1);
                    const n = switch (std.os.errno(counts)) {
                        .SUCCESS => counts,
                        .INTR => continue,
                        else => |err| return std.os.unexpectedErrno(err),
                    };

                    for (events[0..n]) |ev| {
                        const dispatch = @intToEnum(EpollMode, @intCast(usize, ev.data.ptr));
                        switch (dispatch) {
                            .File => {
                                if (@as(u32, ev.events & os.linux.EPOLL.IN) != 0) {
                                    var bytes: [MaxBufBytes]u8 = undefined;
                                    const count = std.os.read(polledfd, &bytes) catch |err| switch (err) {
                                        error.WouldBlock => {
                                            continue;
                                        },
                                        else => return err,
                                    };

                                    try serial_dev.queue_bytes(&bytes[0..count]);
                                }
                            },
                            else => unreachable,
                        }
                    }
                },
                else => @compileError("unsupported Os"),
            }
        }
    }
};
