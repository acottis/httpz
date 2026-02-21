const std = @import("std");
const Allocator = std.mem.Allocator;

const http = @import("http.zig");
const StatusCode = http.Response.StatusCode;

pub fn main() !void {
    var buffer: [1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buffer);
    const allocator = fba.allocator();

    var server = http.Server.init(allocator);
    try server.addPath("/foo", foo);
    try server.listen();
}

fn foo(_: Allocator, req: *const http.Request) !http.Response {
    std.log.info("From path: {s}", .{req.path});
    for (req.headers.items) |header| {
        std.log.debug("{s}: {s}", .{ header.key, header.value });
    }

    var res = http.Response.init(StatusCode.@"200 Ok");
    res.close();
    return res;
}
