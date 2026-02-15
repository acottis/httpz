const std = @import("std");
const log = std.log;
const SIG = std.posix.SIG;

pub var RECIEVED: bool = false;

pub fn register_handler() void {
    const action = std.posix.Sigaction{
        .handler = .{ .handler = handle_signal },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    for ([_]u8{ SIG.INT, SIG.TERM }) |sig| {
        std.posix.sigaction(sig, &action, null);
    }
}

fn handle_signal(sig_num: i32) callconv(.c) void {
    // If this is second time, just die
    if (RECIEVED) {
        log.info("Received Additional Signal {}", .{sig_num});
        std.process.exit(0);
    }
    std.log.info("Received Signal {}", .{sig_num});
    RECIEVED = true;
    std.Thread.sleep(3_000_000_000);
    std.process.exit(0);
}
