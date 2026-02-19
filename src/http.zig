const std = @import("std");
const signal = @import("signal.zig");
const net = std.net;
const log = std.log;
const splitSequence = std.mem.splitSequence;
const stringToEnum = std.meta.stringToEnum;

const THREADS = 1;
// 500 MBs
const MAX_HTTP_PAYLOAD = 1024 * 1024 * 500;

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
    content_length: ?u64,
    body: ?std.ArrayList(u8),

    const ParseError = error{
        BadHeader,
        MissingCRLFCRLF,
        Internal,
        Method,
        Version,
        Bad,
        ContentTooLarge,
    } || std.mem.Allocator.Error || std.io.Reader.Error;

    fn parse(arena: std.mem.Allocator, reader: *std.Io.Reader) ParseError!@This() {
        // Fill the buffer then set end to 0 so the next fill will fill
        // in the first bytes again
        try reader.fillMore();
        const buf = reader.buffer[0..reader.end];
        reader.end = 0;

        var request_parts = splitSequence(u8, buf, "\r\n\r\n");
        var headers_parts = splitSequence(u8, request_parts.first(), "\r\n");
        const body_slice = request_parts.next() orelse return error.MissingCRLFCRLF;

        var first_line = splitSequence(u8, headers_parts.first(), " ");

        const method = stringToEnum(Method, first_line.first()) orelse return ParseError.Method;
        const path = first_line.next() orelse return ParseError.Bad;
        const version_str = first_line.next() orelse return ParseError.Version;
        const version = stringToEnum(Version, version_str) orelse return ParseError.Version;

        var headers = std.ArrayList(Header).initCapacity(arena, 32) catch return ParseError.Internal;
        var content_length: ?u64 = null;
        while (headers_parts.next()) |header| {
            var header_parts = splitSequence(u8, header, ": ");

            const key = header_parts.first();

            const value = header_parts.next() orelse return ParseError.BadHeader;

            const key_lower = try std.ascii.allocLowerString(arena, key);

            if (std.mem.eql(u8, key_lower, "content-length")) {
                content_length = std.fmt.parseInt(u64, value, 10) catch return ParseError.BadHeader;

                if (content_length.? > MAX_HTTP_PAYLOAD) return ParseError.ContentTooLarge;
            }

            try headers.append(arena, .{
                .key = key_lower,
                .value = try arena.dupe(u8, value),
            });
        }

        var body: ?std.ArrayList(u8) = null;
        if (content_length) |total_len| {
            std.log.debug("im here\n, {any}", .{body_slice});
            // Lying about Content Length
            if (body_slice.len > total_len) return ParseError.Bad;
            body = try std.ArrayList(u8).initCapacity(arena, total_len);
            try body.?.appendSlice(arena, body_slice);
        }

        return .{
            .method = method,
            .path = try arena.dupe(u8, path),
            .version = version,
            .headers = headers,
            .content_length = content_length,
            .body = body,
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

fn handle_error(conn: *const net.Server.Connection, err: Request.ParseError) !void {
    std.log.err("Request Parsing {}", .{err});
    switch (err) {
        error.BadHeader => {
            const res = "HTTP/1.0 400 Bad Request - Malformed Header\r\n\r\n";
            _ = try conn.stream.write(res);
        },
        error.MissingCRLFCRLF => {
            const res = "HTTP/1.0 400 Bad Request - Missing CRLFCRLF\r\n\r\n";
            _ = try conn.stream.write(res);
        },
        error.Internal => {
            const res = "HTTP/1.0 500 Internal Server Error\r\n\r\n";
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
}

fn handle(arena: std.mem.Allocator, conn: *const net.Server.Connection) !void {
    log.info("Received conn: {f}", .{conn.address});

    var buf: [1024 * 8]u8 = undefined;
    var stream_reader = conn.stream.reader(&buf);
    const reader = stream_reader.interface();

    var req = Request.parse(arena, reader) catch |err| {
        try handle_error(conn, err);
        return;
    };

    std.log.debug("{}", .{req});
    for (req.headers.items) |header| {
        std.log.debug("{s}: {s}", .{ header.key, header.value });
    }

    // No more bytes expected
    if (req.content_length == null) {
        const res = "HTTP/1.0 204 No Content\r\n\r\n";
        _ = try conn.stream.write(res);
        return;
    }

    // More bytes expected
    const content_length = req.content_length.?;

    var done = false;
    while (!done) {
        // SAFTEFY: We only
        var body = &req.body.?;
        std.log.debug("{}", .{body});

        if (content_length <= body.items.len) {
            done = true;
            const res = "HTTP/1.0 204 No Content\r\n\r\n";
            _ = try conn.stream.write(res);
            return;
        }

        std.log.debug("Need more bytes End: {}, seek: {} body_len {}", .{
            reader.end,
            reader.seek,
            body.items.len,
        });
        reader.fillMore() catch {
            std.log.err("Client {f} disconnected unexpectidly", .{conn.address});
            return;
        };
        std.log.debug("Need more bytes End: {}, seek: {}", .{
            reader.end,
            reader.seek,
        });
        const bytes = reader.buffer[reader.seek..reader.end];
        try body.appendSlice(arena, bytes);
        std.log.debug("{s}, {}, {s}", .{
            bytes,
            body.items.len,
            body.items,
        });
    }
}
