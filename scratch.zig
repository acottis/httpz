const std = @import("std");

const SettingId = enum(u16) {
    HEADER_TABLE_SIZE = 0x1,
    ENABLE_PUSH = 0x2,
    MAX_CONCURRENT_STREAMS = 0x3,
    INITIAL_WINDOW_SIZE = 0x4,
    MAX_FRAME_SIZE = 0x5,
    MAX_HEADER_LIST_SIZE = 0x6,
};

const FrameType = enum(u8) {
    DATA = 0,
    HEADERS = 1,
    PRIORITY = 2,
    RST_STREAM = 3,
    SETTINGS = 4,
    PUSH_PROMISE = 5,
    PING = 6,
    GOAWAY = 7,
    WINDOW_UPDATE = 8,
    CONTINUATION = 9,
};

const Setting = struct {
    id: SettingId,
    value: u32,
};

const Frame = struct {
    ty: FrameType,
    flags: u8 = 0,
    stream: u31 = 0,
    settings: []const Setting,

    const big = std.builtin.Endian.big;

    fn init(ty: FrameType, settings: []const Setting) @This() {
        return .{
            .ty = ty,
            .settings = settings,
        };
    }

    fn serialise(self: *const @This(), writer: *std.Io.Writer) !void {
        const len: u24 = @intCast(@sizeOf(Setting) * self.settings.len);
        _ = try writer.writeInt(u24, len, big);
        _ = try writer.writeByte(@intFromEnum(self.ty));
        _ = try writer.writeByte(self.flags);
        _ = try writer.writeInt(u32, self.stream, big);

        for (self.settings) |setting| {
            _ = try writer.writeInt(u16, @intFromEnum(setting.id), big);
            _ = try writer.writeInt(u32, setting.value, big);
        }
    }
};

pub fn main() !void {
    var buffer: [64]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    const settings: [1]Setting = .{
        .{ .id = .ENABLE_PUSH, .value = 42 },
    };
    const frame = Frame.init(FrameType.SETTINGS, &settings);
    try frame.serialise(&writer);
    std.debug.print("{any}\n", .{writer.buffer});
}

// const Header = struct {
//     key: []const u8,
//     value: []const u8,
// };

// pub fn main() !void {
//     const listener = try std.net.Address.parseIp6("::", 8080);
//     var server = try listener.listen(.{});

//     while (true) {
//         const conn = try server.accept();
//         defer conn.stream.close();

//         var buf: [8 * 1024]u8 = undefined;

//         var stream_reader = conn.stream.reader(&buf);
//         const reader = stream_reader.interface();

//         var bread: u64 = 0;
//         while (true) {
//             reader.fillMore() catch break;
//             bread += reader.end;
//             const s = try reader.take(reader.end);
//             std.debug.print("{s}\n", .{s});
//         }
//         std.debug.print("{}\n", .{bread});
//     }
// }

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
