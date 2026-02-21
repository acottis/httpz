const std = @import("std");
const signal = @import("signal.zig");
const Trie = @import("trie.zig").Trie;
const net = std.net;
const log = std.log;
const posix = std.posix;
const splitSequence = std.mem.splitSequence;
const stringToEnum = std.meta.stringToEnum;

const THREADS = 1;
// 500 MBs
const MAX_CONTENT_LEN = 1024 * 1024 * 500;

const c = @cImport({
    @cDefine("_GNU_SOURCE", "");
    @cInclude("sched.h");
});

const Handler = *const fn (Request) void;

pub const Server = struct {
    paths: Trie(Handler),

    pub fn init(allocator: std.mem.Allocator) @This() {
        return .{
            .paths = Trie(Handler).init(allocator),
        };
    }

    pub fn listen(self: *@This()) !void {
        signal.register_handler();

        const cores = try std.Thread.getCpuCount();
        log.info("System has {} cores", .{cores});
        var threads: [THREADS]std.Thread = undefined;
        for (0..THREADS) |i| {
            const id: u8 = @intCast(i);
            threads[i] = try std.Thread.spawn(.{}, worker, .{
                id,
                &self.paths,
            });
        }

        // Dont exit program while any threads are running
        for (threads) |thread| {
            thread.join();
        }
    }

    pub fn add_path(
        self: *@This(),
        path: []const u8,
        func: Handler,
    ) !void {
        try self.paths.insert(path, func);
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

const Connection = enum {
    close,
    @"keep-alive",
};

const Header = struct {
    key: []const u8,
    value: []const u8,
};

pub const Request = struct {
    method: Method,
    path: []const u8,
    version: Version,
    headers: std.ArrayList(Header),
    body: ?std.ArrayList(u8),
    connection: Connection,

    const ParseError = error{
        /// Content-Length is not a number
        HeaderContentLen,
        /// Connection header is not valid
        HeaderConnection,
        /// Header cannot be parsed
        BadHeader,
        /// Missing \r\n\r\n at end of header
        MissingCRLFCRLF,
        /// We blew up
        Internal,
        /// Method we dont implement
        Method,
        /// Version we dont implement
        Version,
        /// Generic bad request
        Bad,
        /// Content larger than Content-Length
        ContentTooLarge,
        /// Server only accepts Smaller Content-Length's
        MaxContentLenExceeded,
    } || std.mem.Allocator.Error || std.Io.Reader.Error;

    inline fn complete(self: *@This()) bool {
        if (self.content_len() == 0) return true;
        if (self.content_len() == self.body.?.items.len) return true;
        return false;
    }

    inline fn content_len(self: *@This()) usize {
        if (self.body != null) return self.body.?.capacity else return 0;
    }

    inline fn keepAlive(self: *@This()) bool {
        return switch (self.connection) {
            Connection.@"keep-alive" => true,
            Connection.close => false,
        };
    }

    fn parse(arena: std.mem.Allocator, reader: *std.io.Reader) ParseError!@This() {
        // Fill the buffer then set readers end to 0 so the next fill will
        // fill in the first bytes again
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

        var maybe_content_ln: ?u64 = null;
        var connection: Connection = if (version != Version.@"HTTP/1.0") Connection.@"keep-alive" else Connection.close;

        // TODO: Maybe move the specific key checkouts out
        while (headers_parts.next()) |header| {
            var header_parts = splitSequence(u8, header, ": ");

            const key = header_parts.first();

            const value = header_parts.next() orelse return ParseError.BadHeader;

            const key_lower = try std.ascii.allocLowerString(arena, key);

            if (std.mem.eql(u8, key_lower, "content-length")) {
                maybe_content_ln = std.fmt.parseInt(u64, value, 10) catch return ParseError.HeaderContentLen;

                if (maybe_content_ln.? > MAX_CONTENT_LEN) return ParseError.MaxContentLenExceeded;
                continue;
            }
            if (std.mem.eql(u8, key_lower, "connection")) {
                connection = stringToEnum(Connection, value) orelse return ParseError.HeaderConnection;
                continue;
            }

            try headers.append(arena, .{ .key = key_lower, .value = try arena.dupe(u8, value) });
        }

        var body: ?std.ArrayList(u8) = null;
        if (maybe_content_ln) |content_ln| {
            // Lying about Content Length
            if (body_slice.len > content_ln) return ParseError.Bad;
            body = try std.ArrayList(u8).initCapacity(arena, content_ln);
            try body.?.appendSlice(arena, body_slice);
        }

        return .{
            .method = method,
            .path = try arena.dupe(u8, path),
            .version = version,
            .headers = headers,
            .body = body,
            .connection = connection,
        };
    }

    fn parseMore(
        self: *@This(),
        arena: std.mem.Allocator,
        reader: *std.io.Reader,
    ) ParseError!bool {
        if (self.complete()) return true;

        const body = &self.body.?;

        try reader.fillMore();
        const bytes_read = body.items.len + reader.end;
        if (bytes_read > self.content_len()) {
            return Request.ParseError.ContentTooLarge;
        }

        const bytes = reader.buffer[reader.seek..reader.end];
        reader.end = 0;

        try body.appendSlice(arena, bytes);

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

fn handleError(conn: *const net.Server.Connection, err: Request.ParseError) !void {
    log.err("Request Parsing {}", .{err});
    const res = switch (err) {
        error.BadHeader => "HTTP/1.1 400 Bad Request - Malformed Header\r\n\r\n",
        error.MissingCRLFCRLF => "HTTP/1.1 400 Bad Request - Missing CRLFCRLF\r\n\r\n",
        error.ContentTooLarge => "HTTP/1.1 400 Bad Request - Content Too Large\r\n\r\n",
        error.Internal => "HTTP/1.1 500 Internal Server Error\r\n\r\n",
        error.Method => "HTTP/1.1 501 Not Implemented\r\n\r\n",
        error.Version => "HTTP/1.1 505 HTTP Version Not Supported\r\n\r\n",
        else => "HTTP/1.1 400 Bad Request\r\n\r\n",
    };
    _ = try conn.stream.write(res);
}

fn handle(arena: std.mem.Allocator, conn: *const net.Server.Connection, paths: *const Trie(Handler)) Request.ParseError!bool {
    var buf: [1024 * 8]u8 = undefined;
    var stream_reader = conn.stream.reader(&buf);
    const reader = stream_reader.interface();

    var req = try Request.parse(arena, reader);

    for (req.headers.items) |header| {
        log.debug("{s}: {s}", .{ header.key, header.value });
    }

    var done = false;
    while (!done) {
        done = try req.parseMore(arena, reader);
    }

    if (paths.search(req.path)) |func| {
        func(req);
    }

    // TODO: User defined functionality here
    const res = "HTTP/1.1 204 No Content\r\n\r\n";
    _ = conn.stream.write(res) catch |err| log.err("Failed to respond {}", .{err});

    return req.keepAlive();
}

fn worker(id: u16, paths: *const Trie(Handler)) !void {
    log.info("Starting worker {}", .{id});

    // Prevent allocating to a core we dont have
    const max_cores = try std.Thread.getCpuCount();
    try pinToCore(@intCast(id % max_cores));

    var allocator = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const arena = allocator.allocator();

    const address = net.Address.initIp6(comptime [_]u8{0} ** 16, 8080, 0, 0);
    const options = net.Address.ListenOptions{ .reuse_address = true };

    var listener = try address.listen(options);
    defer listener.deinit();

    const timeout = posix.timeval{ .sec = 5, .usec = 0 };
    while (!signal.RECIEVED) {
        _ = allocator.reset(.retain_capacity);
        const conn = try listener.accept();
        defer conn.stream.close();
        log.info("Received conn: {f}", .{conn.address});

        try posix.setsockopt(
            conn.stream.handle,
            posix.SOL.SOCKET,
            posix.SO.RCVTIMEO,
            &std.mem.toBytes(timeout),
        );

        var keepAlive = true;
        while (keepAlive) {
            keepAlive = handle(arena, &conn, paths) catch |err| {
                switch (err) {
                    std.Io.Reader.Error.ReadFailed => log.debug("{f} timed out", .{conn.address}),
                    std.Io.Reader.Error.EndOfStream => log.debug("{f} closed connection", .{conn.address}),
                    else => try handleError(&conn, err),
                }
                break;
            };
        }
    }
}
