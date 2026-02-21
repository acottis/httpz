const std = @import("std");

const http = @import("http.zig");

pub fn main() !void {
    var buffer: [1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buffer);
    const allocator = fba.allocator();

    var server = http.Server.init(allocator);
    try server.add_path("/foo", foo);
    try server.listen();
}

fn foo(req: http.Request) void {
    std.log.info("From path: {s}", .{req.path});
}
