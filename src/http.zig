const std = @import("std");
const signal = @import("signal.zig");
const net = std.net;
const log = std.log;
const splitSequence = std.mem.splitSequence;
const stringToEnum = std.meta.stringToEnum;

const THREADS = 1;
// 500 MBs
const MAX_CONTENT_LEN = 1024 * 1024 * 500;

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
        log.info("System has {} cores", .{cores});
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
    content_len: ?u64,
    body: ?std.ArrayList(u8),

    const ParseError = error{
        BadHeader,
        MissingCRLFCRLF,
        Internal,
        Method,
        Version,
        Bad,
        ContentTooLarge,
        MaxContentLenExceeded,
    } || std.mem.Allocator.Error || std.Io.Reader.Error;

    /// SAFTEFY: Only call this if content_len and body != null
    fn complete(self: *@This()) bool {
        std.debug.assert(self.content_len != null);

        if (self.content_len.? == self.body.?.items.len) return true;
        return false;
    }

    fn parse(arena: std.mem.Allocator, reader: *std.io.Reader) ParseError!@This() {
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
        var maybe_content_len: ?u64 = null;
        while (headers_parts.next()) |header| {
            var header_parts = splitSequence(u8, header, ": ");

            const key = header_parts.first();

            const value = header_parts.next() orelse return ParseError.BadHeader;

            const key_lower = try std.ascii.allocLowerString(arena, key);

            if (std.mem.eql(u8, key_lower, "content-length")) {
                maybe_content_len = std.fmt.parseInt(u64, value, 10) catch return ParseError.BadHeader;

                if (maybe_content_len.? > MAX_CONTENT_LEN) return ParseError.MaxContentLenExceeded;
            }

            try headers.append(arena, .{
                .key = key_lower,
                .value = try arena.dupe(u8, value),
            });
        }

        var body: ?std.ArrayList(u8) = null;
        if (maybe_content_len) |content_len| {
            // Lying about Content Length
            if (body_slice.len > content_len) return ParseError.Bad;
            body = try std.ArrayList(u8).initCapacity(arena, content_len);
            try body.?.appendSlice(arena, body_slice);
        }

        return .{
            .method = method,
            .path = try arena.dupe(u8, path),
            .version = version,
            .headers = headers,
            .content_len = maybe_content_len,
            .body = body,
        };
    }

    /// SAFTEFY: Only call this if content_len and body != null
    fn parseMore(
        self: *@This(),
        arena: std.mem.Allocator,
        reader: *std.io.Reader,
    ) ParseError!bool {
        std.debug.assert(self.content_len != null);

        const body = &self.body.?;
        const content_len = self.content_len.?;
        log.debug("{}", .{body});

        try reader.fillMore();
        const bytes_read = body.items.len + reader.end;
        if (bytes_read > content_len) {
            return Request.ParseError.ContentTooLarge;
        }

        const bytes = reader.buffer[reader.seek..reader.end];
        reader.end = 0;

        try body.appendSlice(arena, bytes);

        if (self.complete()) return true;
        return false;
    }
};

fn pinToCore(core: u16) !void {
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
    try pinToCore(@intCast(id % max_cores));

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
        handle(arena, &conn) catch |err| {
            try handleError(&conn, err);
            continue;
        };
        const res = "HTTP/1.0 204 No Content\r\n\r\n";
        _ = try conn.stream.write(res);
    }
}

fn handleError(conn: *const net.Server.Connection, err: Request.ParseError) !void {
    log.err("Request Parsing {}", .{err});
    const res = switch (err) {
        error.BadHeader => "HTTP/1.0 400 Bad Request - Malformed Header\r\n\r\n",
        error.MissingCRLFCRLF => "HTTP/1.0 400 Bad Request - Missing CRLFCRLF\r\n\r\n",
        error.ContentTooLarge => "HTTP/1.0 400 Bad Request - Content Too Large\r\n\r\n",
        error.Internal => "HTTP/1.0 500 Internal Server Error\r\n\r\n",
        error.Method => "HTTP/1.0 501 Not Implemented\r\n\r\n",
        error.Version => "HTTP/1.0 505 HTTP Version Not Supported\r\n\r\n",
        else => "HTTP/1.0 400 Bad Request\r\n\r\n",
    };
    _ = try conn.stream.write(res);
}

fn handle(arena: std.mem.Allocator, conn: *const net.Server.Connection) Request.ParseError!void {
    log.info("Received conn: {f}", .{conn.address});

    var buf: [1024 * 8]u8 = undefined;
    var stream_reader = conn.stream.reader(&buf);
    const reader = stream_reader.interface();

    var req = try Request.parse(arena, reader);

    log.debug("{}", .{req});
    for (req.headers.items) |header| {
        log.debug("{s}: {s}", .{ header.key, header.value });
    }

    // No more bytes expected
    if (req.content_len == null) return;

    // All bytes account for
    if (req.complete()) return;

    var done = false;
    while (!done) {
        done = try req.parseMore(arena, reader);
    }
}
