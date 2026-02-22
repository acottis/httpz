const std = @import("std");

pub const Setting = struct {
    id: Id,
    value: u32,

    const Id = enum(u16) {
        HEADER_TABLE_SIZE = 0x1,
        ENABLE_PUSH = 0x2,
        MAX_CONCURRENT_STREAMS = 0x3,
        INITIAL_WINDOW_SIZE = 0x4,
        MAX_FRAME_SIZE = 0x5,
        MAX_HEADER_LIST_SIZE = 0x6,
    };
};

pub const Frame = struct {
    ty: Ty,
    flags: u8 = 0,
    stream: u31 = 0,
    settings: []const Setting,

    const big = std.builtin.Endian.big;

    const Ty = enum(u8) {
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

    pub fn init(ty: Ty, settings: []const Setting) @This() {
        return .{
            .ty = ty,
            .settings = settings,
        };
    }

    pub fn serialise(self: *const @This(), writer: *std.Io.Writer) !void {
        const len: u24 = @intCast(@sizeOf(Setting) * self.settings.len);
        std.debug.print("{}, {}\n", .{ len, @sizeOf(Setting) });
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
