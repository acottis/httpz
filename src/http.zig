const std = @import("std");
const net = std.net;
const log = std.log;
const posix = std.posix;
const splitSequence = std.mem.splitSequence;
const stringToEnum = std.meta.stringToEnum;
const eql = std.mem.eql;
const Allocator = std.mem.Allocator;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

const signal = @import("signal.zig");
const Trie = @import("trie.zig").Trie;
const http2 = @import("http2.zig");

const THREADS = 2;
// 500 MBs - Arbitory limit
const MAX_CONTENT_LEN = 1024 * 1024 * 500;

const c = @cImport({
    @cDefine("_GNU_SOURCE", "");
    @cInclude("sched.h");
});

const Handler = *const fn (Allocator, *const Request) anyerror!Response;

pub const Server = struct {
    paths: Trie(Handler),

    /// Allocator is only for top level state, allocations to do with
    /// indidual is handled internally
    pub fn init(allocator: Allocator) @This() {
        return .{
            .paths = Trie(Handler).init(allocator),
        };
    }

    pub fn listen(self: *const @This()) !void {
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

    pub fn addPath(
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

const Connection = packed struct {
    keep_alive: bool = false,
    /// Close has priority over KeepAlive
    close: bool = false,
    upgrade: bool = false,
    http2_settings: bool = false,
};

pub const Header = struct {
    key: []const u8,
    value: []const u8,

    pub fn init(alloc: Allocator, key: []const u8, value: []const u8) !@This() {
        return .{
            .key = try alloc.dupe(u8, key),
            .value = try alloc.dupe(u8, value),
        };
    }
};

const Error = error{} || Request.ParseError || std.Io.Writer.Error;

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
    } || Allocator.Error || Reader.Error;

    inline fn complete(self: *@This()) bool {
        if (self.content_len() == 0) return true;
        if (self.content_len() == self.body.?.items.len) return true;
        return false;
    }

    inline fn content_len(self: *@This()) usize {
        if (self.body != null) return self.body.?.capacity else return 0;
    }

    inline fn keepAlive(self: *@This()) bool {
        if (self.connection.close) return false;

        if (self.version == .@"HTTP/1.0" and !self.connection.keep_alive) return false;

        return true;
    }

    fn parseHttp1(alloc: Allocator, reader: *Reader) !@This() {
        const buf = reader.buffered();
        // Set reader end to 0 so the next fill will fill in the first
        // bytes again on next fill
        reader.end = 0;
        var request_parts = splitSequence(u8, buf, "\r\n\r\n");
        var headers_parts = splitSequence(u8, request_parts.first(), "\r\n");
        const body_slice = request_parts.next() orelse return ParseError.MissingCRLFCRLF;

        var first_line = splitSequence(u8, headers_parts.first(), " ");

        const method = stringToEnum(Method, first_line.first()) orelse return ParseError.Method;
        const path = first_line.next() orelse return ParseError.Bad;
        const version_str = first_line.next() orelse return ParseError.Version;
        const version = stringToEnum(Version, version_str) orelse return ParseError.Version;

        var headers = std.ArrayList(Header).initCapacity(alloc, 32) catch return ParseError.Internal;

        var maybe_content_ln: ?u64 = null;
        var connection = Connection{};

        // TODO: Maybe move the specific key checkouts out
        while (headers_parts.next()) |header| {
            var header_parts = splitSequence(u8, header, ": ");

            const key = header_parts.first();
            const value = header_parts.next() orelse return ParseError.BadHeader;

            const key_lower = try std.ascii.allocLowerString(alloc, key);

            if (eql(u8, key_lower, "content-length")) {
                maybe_content_ln = std.fmt.parseInt(u64, value, 10) catch return ParseError.HeaderContentLen;

                if (maybe_content_ln.? > MAX_CONTENT_LEN) return ParseError.MaxContentLenExceeded;
                continue;
            }
            if (eql(u8, key_lower, "connection")) {
                var tokens = splitSequence(u8, value, ", ");
                while (tokens.next()) |token| {
                    _ = std.ascii.lowerString(@constCast(token), token);

                    if (eql(u8, token, "close")) {
                        connection.close = true;
                    } else if (std.ascii.eqlIgnoreCase(token, "keep-alive")) {
                        connection.keep_alive = true;
                    } else if (eql(u8, token, "upgrade")) {
                        connection.upgrade = true;
                    } else if (eql(u8, token, "http2-settings")) {
                        connection.http2_settings = true;
                    } else {
                        log.warn("Unhandled connection token: {s}", .{token});
                    }
                }
                continue;
            }

            try headers.append(alloc, .{ .key = key_lower, .value = try alloc.dupe(u8, value) });
        }

        var body: ?std.ArrayList(u8) = null;
        if (maybe_content_ln) |content_ln| {
            // Lying about Content Length
            if (body_slice.len > content_ln) return ParseError.Bad;
            body = try std.ArrayList(u8).initCapacity(alloc, content_ln);
            try body.?.appendSlice(alloc, body_slice);
        }

        return .{
            .method = method,
            .path = try alloc.dupe(u8, path),
            .version = version,
            .headers = headers,
            .body = body,
            .connection = connection,
        };
    }

    // TODO: Half implemented
    fn parseHttp2(_: Allocator, reader: *Reader) ParseError!@This() {

        // Skip magic
        reader.toss(24);
        while (reader.bufferedLen() > 9) {
            const frame = try http2.Frame.parse(reader);
            if (frame.ty == .headers) {
                var r = std.Io.Reader.fixed(@constCast(frame.payload));
                _ = http2.Headers.parse(&r);
            }
        }
        @panic("");

        // return .{
        //     .method = .GET,
        //     .path = "",
        //     .version = .@"HTTP/2.0",
        //     .headers = std.ArrayList(Header).empty,
        //     .body = null,
        //     .connection = Connection{},
        // };
    }

    fn parse(
        arena: Allocator,
        reader: *Reader,
        mode: *Session.Mode,
    ) ParseError!@This() {
        if (mode.* == .detecting) {
            // Even although we only peek 3 the underlying buffer is
            // filled as much as possible
            const magic = try reader.peek(3);
            mode.* = if (eql(u8, magic, "PRI")) .http2 else .http1;
        } else {
            try reader.fillMore();
        }

        if (mode.* == .http2) {
            return try parseHttp2(arena, reader);
        } else {
            return try parseHttp1(arena, reader);
        }
    }

    fn parseMore(
        self: *@This(),
        arena: Allocator,
        reader: *std.io.Reader,
    ) ParseError!bool {
        if (self.complete()) return true;

        const body = &self.body.?;

        try reader.fillMore();
        const bytes_read = body.items.len + reader.end;
        if (bytes_read > self.content_len()) {
            return Request.ParseError.ContentTooLarge;
        }

        const bytes = reader.buffered();
        reader.end = 0;

        try body.appendSlice(arena, bytes);

        return false;
    }
};

pub const Response = struct {
    version: Version,
    status_code: StatusCode,
    connection: Connection,
    headers: std.ArrayList(Header),
    body: ?std.ArrayList(u8) = null,

    pub const StatusCode = enum {
        @"101 Switching Protocols",
        @"200 Ok",
        @"204 No Content",
        @"400 Bad Request",
        @"404 Not Found",
        @"500 Internal Server Error",
        @"501 Not Implemented",
        @"505 HTTP Version Not Supported",
    };

    pub fn init(
        status_code: StatusCode,
    ) @This() {
        return .{
            .version = .@"HTTP/1.1",
            .status_code = status_code,
            .connection = Connection{},
            .headers = std.ArrayList(Header).empty,
        };
    }

    pub fn h2c() @This() {
        return .{
            .version = .@"HTTP/1.1",
            .status_code = .@"101 Switching Protocols",
            .connection = Connection{ .upgrade = true },
            .headers = std.ArrayList(Header).empty,
        };
    }

    pub fn setBody(self: *@This(), alloc: Allocator, body: []const u8) !void {
        self.body = std.ArrayList(u8).empty;
        try self.body.?.appendSlice(alloc, body);
    }

    pub fn setHeader(
        self: *@This(),
        alloc: Allocator,
        key: []const u8,
        value: []const u8,
    ) !void {
        const header = try Header.init(alloc, key, value);
        try self.headers.append(alloc, header);
    }

    pub fn close(self: *@This()) void {
        self.connection = .close;
    }

    pub inline fn noContent() @This() {
        return init(.@"204 No Content");
    }

    pub inline fn notFound() @This() {
        return init(.@"404 Not Found");
    }

    pub inline fn internalServerError() @This() {
        return init(.@"500 Internal Server Error");
    }

    fn serialise(self: *const @This(), writer: *std.io.Writer) !void {
        try writer.print("{s} {s}\r\n", .{
            @tagName(self.version),
            @tagName(self.status_code),
        });

        // Early exit if upgrading
        if (self.connection.upgrade) {
            _ = try writer.write("Connection: Upgrade\r\n");
            _ = try writer.write("Upgrade: h2c\r\n");
            _ = try writer.write("\r\n");
            try writer.flush();

            // const frame = http2.Frame.init(.settings, &.{});
            // try frame.serialise(writer);
            // try writer.flush();
            return;
        }

        const content_len = if (self.body) |b| b.items.len else 0;
        try writer.print("Content-Length: {}\r\n", .{content_len});
        if (self.connection.close) {
            _ = try writer.write("Connection: close\r\n");
        }
        for (self.headers.items) |header| {
            try writer.print("{s}: {s}\r\n", .{ header.key, header.value });
        }
        _ = try writer.write("\r\n");

        if (self.body) |body| {
            try writer.print("{s}", .{body.items});
        }
        try writer.flush();
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

fn handleError(conn: *const net.Server.Connection, err: Error) Writer.Error!void {
    // Client disconnect session, not an error for us
    if (err == Reader.Error.EndOfStream) {
        log.debug("{f} closed connection", .{conn.address});
        return;
    }

    log.err("Request Parsing {}", .{err});
    const res = switch (err) {
        Reader.Error.ReadFailed => {
            log.debug("{f} timed out", .{conn.address});
            return;
        },
        Writer.Error.WriteFailed => {
            log.debug("{f} Failed to write to client", .{conn.address});
            return;
        },
        error.Internal => Response.init(.@"500 Internal Server Error"),
        error.Method => Response.init(.@"501 Not Implemented"),
        error.Version => Response.init(.@"505 HTTP Version Not Supported"),
        else => Response.init(.@"400 Bad Request"),
    };
    var buf: [1024]u8 = undefined;
    var writer = conn.stream.writer(&buf);
    try res.serialise(&writer.interface);
}

fn handleRequest(
    arena: Allocator,
    paths: *const Trie(Handler),
    req: *const Request,
) Response {
    if (paths.search(req.path)) |func| {
        return func(arena, req) catch |err| {
            log.err("{} in Handler func for path {s}", .{ err, req.path });
            return Response.internalServerError();
        };
    } else {
        return Response.notFound();
    }
}

const Session = struct {
    alloc: Allocator,
    conn: *const net.Server.Connection,
    mode: Mode = .detecting,
    paths: *const Trie(Handler),
    keep_alive: bool = true,

    const Mode = enum {
        detecting,
        http1,
        http2,
    };

    fn init(
        alloc: Allocator,
        conn: *const net.Server.Connection,
        paths: *const Trie(Handler),
    ) @This() {
        return .{
            .alloc = alloc,
            .conn = conn,
            .paths = paths,
        };
    }

    fn handle(self: *@This()) Error!void {
        var buf: [1024 * 8]u8 = undefined;
        var stream_reader = self.conn.stream.reader(&buf);
        const reader = stream_reader.interface();

        var req = try Request.parse(self.alloc, reader, &self.mode);

        // Handle h2c upgrade
        if (req.connection.upgrade) {
            const res = Response.h2c();
            var writer = self.conn.stream.writer(&buf);
            try res.serialise(&writer.interface);
            try writer.interface.flush();
            return;
        }

        var done = false;
        while (!done) {
            done = try req.parseMore(self.alloc, reader);
        }

        const res = handleRequest(self.alloc, self.paths, &req);

        var writer = self.conn.stream.writer(&buf);
        try res.serialise(&writer.interface);

        self.keep_alive = if (res.connection.close) true else req.keepAlive();
    }
};

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
    const timeos = [_]u32{ posix.SO.RCVTIMEO, posix.SO.SNDTIMEO };

    while (!signal.RECIEVED) {
        _ = allocator.reset(.retain_capacity);
        const conn = try listener.accept();
        defer conn.stream.close();
        log.info("Received conn: {f}", .{conn.address});

        for (timeos) |timeo| {
            try posix.setsockopt(
                conn.stream.handle,
                posix.SOL.SOCKET,
                timeo,
                &std.mem.toBytes(timeout),
            );
        }

        var session = Session.init(arena, &conn, paths);
        while (session.keep_alive) {
            session.handle() catch |err| {
                try handleError(&conn, err);
                break;
            };
        }
    }
}
