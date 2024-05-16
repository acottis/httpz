const std = @import("std");
const http = @import("./http.zig");

pub const std_options = .{ .log_level = .info };

pub fn main() !void {
    var server = try http.Server.bind();
    try server.add_path("/", root);
    try server.listen();
}

fn root(req: http.HttpRequest) void {
    std.log.debug("{any}\n", .{req});
}
