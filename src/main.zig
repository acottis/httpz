const std = @import("std");
const net = std.net;
const log = std.log;

const signal = @import("signal.zig");

const THREADS = 1;

const c = @cImport({
    @cDefine("_GNU_SOURCE", "");
    @cInclude("sched.h");
});

fn pin_to_core(core: u16) !void {
    var cpu_set = c.cpu_set_t{};
    const index = core / 64;
    const bit: u6 = @intCast(core % 64);
    cpu_set.__bits[index] |= @as(u64, 1) << bit;
    const ret = c.sched_setaffinity(0, @sizeOf(std.c.cpu_set_t), &cpu_set);
    if (ret != 0) {
        const err = @tagName(std.posix.errno(ret));
        log.err("{s}: Pinning core {}", .{ err, core });
        return error.PinThread;
    }
}

fn worker(id: u16) !void {
    log.info("Starting worker {}", .{id});

    const max_cores = try std.Thread.getCpuCount();
    try pin_to_core(@intCast(id % max_cores));

    const address = net.Address.initIp6([_]u8{0} ** 16, 8080, 0, 0);
    const options = net.Address.ListenOptions{
        .reuse_address = true,
    };
    var listener = try address.listen(options);
    defer listener.deinit();

    const res = if (id == 0) "HTTP/1.0 204 NO CONTENT\r\n\r\n" else "HTTP/1.1 204 NO CONTENT\r\n\r\n";

    while (!signal.RECIEVED) {
        const conn = try listener.accept();
        defer conn.stream.close();
        log.info("Recieved conn: {f}", .{conn.address});

        _ = try conn.stream.write(res);
    }
}
pub fn main() !void {
    signal.register_handler();

    const cores = try std.Thread.getCpuCount();
    std.log.info("System has {} cores", .{cores});
    var handles: [THREADS]std.Thread = undefined;
    for (0..THREADS) |i| {
        const id: u8 = @intCast(i);
        handles[i] = try std.Thread.spawn(.{}, worker, .{id});
    }

    // Dont exit program while any threads are running
    for (handles) |handle| {
        handle.join();
    }
}
