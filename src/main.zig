const std = @import("std");
const http = @import("./http.zig");

pub const std_options = .{ .log_level = .info };

pub fn main() !void {
    try (try (try http.Server.bind()).add_path("/", root)).listen();
}

fn root(req: http.HttpRequest) void {
    std.log.info("{any}", .{req});
}
