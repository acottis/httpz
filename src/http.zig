const std = @import("std");
const signal = @import("signal.zig");
const net = std.net;
const log = std.log;
const splitSequence = std.mem.splitSequence;
const stringToEnum = std.meta.stringToEnum;

const THREADS = 1;

const c = @cImport({
    @cDefine("_GNU_SOURCE", "");
    @cInclude("sched.h");
});

pub const Server = struct {
    pub fn init() @This() {
        return @This(){};
    }
    pub fn listen() !void {
        signal.register_handler();

        const cores = try std.Thread.getCpuCount();
        std.log.info("System has {} cores", .{cores});
        var threads: [THREADS]std.Thread = undefined;
        for (0..THREADS) |i| {
            const id: u8 = @intCast(i);
            threads[i] = try std.Thread.spawn(.{}, worker, .{id});
        }

        // Dont exit program while any threads are running
        for (threads) |thread| {
            thread.join();
        }
    }
};

const Method = enum {
    GET,
    POST,
};

const Version = enum {
    @"HTTP/1.0",
    @"HTTP/1.1",
    @"HTTP/2.0",
};

const Header = struct {
    key: []const u8,
    value: []const u8,
};

const Request = struct {
    method: Method,
    path: []const u8,
    version: Version,
    headers: std.ArrayList(Header),

    fn parse(arena: std.mem.Allocator, buf: []u8) !@This() {
        var request_parts = splitSequence(u8, buf, "\r\n\r\n");

        var headers_parts = splitSequence(u8, request_parts.first(), "\r\n");
        var first_line = splitSequence(u8, headers_parts.first(), " ");

        const method = stringToEnum(Method, first_line.first()) orelse return error.Method;
        const path = first_line.next() orelse return error.Bad;
        const version_str = first_line.next() orelse return error.Bad;
        const version = stringToEnum(Version, version_str) orelse return error.Version;

        var headers = std.ArrayList(Header).initCapacity(arena, 32) catch return error.Internal;
        while (headers_parts.next()) |header| {
            var header_parts = splitSequence(u8, header, ": ");
            const key = header_parts.first();
            const value = header_parts.next() orelse return error.BadHeader;

            headers.append(arena, .{
                .key = arena.dupe(u8, key) catch return error.Oom,
                .value = arena.dupe(u8, value) catch return error.Oom,
            }) catch return error.Oom;
        }

        return .{
            .method = method,
            .path = arena.dupe(u8, path) catch return error.Oom,
            .version = version,
            .headers = headers,
        };
    }
};

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

    // Prevent allocating to a core we dont have
    const max_cores = try std.Thread.getCpuCount();
    try pin_to_core(@intCast(id % max_cores));

    var allocator = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const arena = allocator.allocator();

    const address = net.Address.initIp6([_]u8{0} ** 16, 8080, 0, 0);
    const options = net.Address.ListenOptions{ .reuse_address = true };

    var listener = try address.listen(options);
    defer listener.deinit();

    while (!signal.RECIEVED) {
        _ = allocator.reset(.retain_capacity);
        const conn = try listener.accept();
        defer conn.stream.close();
        try handle(arena, &conn);
    }
}

fn handle(arena: std.mem.Allocator, conn: *const net.Server.Connection) !void {
    log.info("Received conn: {f}", .{conn.address});

    var buf: [1024]u8 = undefined;
    const len = try conn.stream.read(&buf);

    const req = Request.parse(arena, buf[0..len]) catch |err| {
        switch (err) {
            error.Internal => {
                const res = "HTTP/1.0 50 Internal Server Error\r\n\r\n";
                _ = try conn.stream.write(res);
            },
            error.Method => {
                const res = "HTTP/1.0 501 Not Implemented\r\n\r\n";
                _ = try conn.stream.write(res);
            },
            error.Version => {
                const res = "HTTP/1.0 505 HTTP Version Not Supported\r\n\r\n";
                _ = try conn.stream.write(res);
            },
            else => {
                const res = "HTTP/1.0 400 Bad Request\r\n\r\n";
                _ = try conn.stream.write(res);
            },
        }
        return;
    };

    std.log.debug("{}", .{req});
    for (req.headers.items) |header| {
        std.log.debug("{s}: {s}", .{ header.key, header.value });
    }

    const res = "HTTP/1.0 204 No Content\r\n\r\n";
    _ = try conn.stream.write(res);
}
