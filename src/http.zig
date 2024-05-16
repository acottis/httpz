const std = @import("std");

fn handle(conn: std.net.Server.Connection) !void {
    defer conn.stream.close();
    std.debug.print("{}\n", .{conn.address});

    var recv_buf = comptime [_]u8{0} ** 1024;
    const len = try conn.stream.read(&recv_buf);

    _ = try HttpRequest.parse(recv_buf[0..len]);
}

const HttpHandler = *const fn (HttpRequest) void;

pub const Server = struct {
    address: std.net.Address,
    paths: std.StringHashMap(HttpHandler),

    pub fn bind() !Server {
        var paths = std.StringHashMap(*const fn (HttpRequest) void).init(std.heap.page_allocator);
        defer paths.deinit();

        return @This(){
            .address = try std.net.Address.parseIp("0.0.0.0", 8080),
            .paths = paths,
        };
    }

    pub fn add_path(self: *Server, path: []const u8, handler: HttpHandler) !void {
        try self.paths.put(path, handler);
    }

    pub fn listen(self: *Server) !void {
        std.log.info("Starting server on port: {}", .{self.address.getPort()});
        var server = try self.address.listen(.{});
        while (true) {
            const conn = try server.accept();

            _ = try std.Thread.spawn(.{}, handle, .{conn});
        }
    }
};

pub const HttpRequest = struct {
    method: []const u8,
    path: []const u8,
    protocol: []const u8,
    body: []const u8,

    fn parse(bytes: []const u8) !HttpRequest {
        const raw = std.unicode.fmtUtf8(bytes);
        std.log.debug("{any}\n", .{raw});

        var split = std.mem.splitSequence(u8, bytes, "\r\n\r\n");
        const headers = split.next().?;
        const body = split.next().?;

        var first_line = std.mem.splitScalar(u8, headers, ' ');
        const method = first_line.next().?;
        const path = first_line.next().?;
        const protocol = first_line.next().?;

        return HttpRequest{ .method = method, .body = body, .path = path, .protocol = protocol };
    }
};
