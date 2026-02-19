const std = @import("std");

const http = @import("http.zig");

pub fn main() !void {
    _ = try http.Server.listen();
}
