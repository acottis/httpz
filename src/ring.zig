const std = @import("std");
const net = std.net;

const Event = enum(u8) { accept = 0, read = 1, send = 2 };

pub fn main() !void {
    const address = net.Address.initIp6([_]u8{0} ** 16, 8080, 0, 0);
    const options = net.Address.ListenOptions{ .reuse_address = true, .force_nonblocking = true };
    var listener = try address.listen(options);
    defer listener.deinit();

    var ring = try std.os.linux.IoUring.init(4, 0);
    defer ring.deinit();

    var sock_addr: std.os.linux.sockaddr = undefined;
    var sock_len: std.os.linux.socklen_t = @sizeOf(std.os.linux.sockaddr);

    std.log.info("Listening on {f}", .{listener.listen_address});
    _ = try ring.accept_multishot(
        @intFromEnum(Event.accept),
        listener.stream.handle,
        &sock_addr,
        &sock_len,
        0,
    );
    _ = try ring.submit();
    while (true) {
        const cqe = try ring.copy_cqe();
        std.debug.print("{}\n", .{cqe});
        const event: Event = @enumFromInt(cqe.user_data);
        switch (event) {
            .send => continue,
            .accept => {
                const stream = net.Stream{ .handle = cqe.res };
                defer stream.close();
                std.debug.print("{}\n{}\n", .{ sock_addr, sock_len });
                _ = try ring.send(
                    @intFromEnum(Event.send),
                    stream.handle,
                    "HTTP/1.1 204 NO CONTENT\r\n\r\n",
                    0,
                );
                _ = try ring.submit();
            },
            .read => {},
        }
    }
}
