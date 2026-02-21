const std = @import("std");

const Header = struct {
    key: []const u8,
    value: []const u8,
};

pub fn main() !void {
    const listener = try std.net.Address.parseIp6("::", 8080);
    var server = try listener.listen(.{});

    while (true) {
        const conn = try server.accept();
        defer conn.stream.close();

        var buf: [8 * 1024]u8 = undefined;

        var stream_reader = conn.stream.reader(&buf);
        const reader = stream_reader.interface();

        var bread: u64 = 0;
        while (true) {
            reader.fillMore() catch break;
            bread += reader.end;
            const s = try reader.take(reader.end);
            std.debug.print("{s}\n", .{s});
        }
        std.debug.print("{}\n", .{bread});
    }
}

// const file = try std.fs.cwd().openFile("foo.txt", .{});

// var buf: [50]u8 = undefined;
// var reader = file.reader(&buf);

// pub const Server = struct {
//     address: std.net.Address,
//     paths: std.StringHashMap(HttpHandler),

//     pub fn bind() !@This() {
//         var paths = std.StringHashMap(*const fn (HttpRequest) void).init(std.heap.page_allocator);
//         defer paths.deinit();

//         return @This(){
//             .address = try std.net.Address.parseIp("0.0.0.0", 8080),
//             .paths = paths,
//         };
//     }

//     pub fn add_path(self: *@This(), path: []const u8, handler: HttpHandler) !*@This() {
//         try self.paths.put(path, handler);
//         return self;
//     }

//     pub fn listen(self: *@This()) !void {
//         std.log.info("Starting server on port: {}", .{self.address.getPort()});
//         var server = try self.address.listen(.{});
//         while (true) {
//             const conn = try server.accept();

//             _ = try std.Thread.spawn(.{}, handle, .{ conn, &self.paths });
//         }
//     }
// };
