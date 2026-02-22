const std = @import("std");

pub const Setting = struct {
    id: Id,
    value: u32,

    const Id = enum(u16) {
        header_table_size = 1,
        enable_push = 2,
        max_concurrent_streams = 3,
        initial_window_size = 4,
        max_frame_size = 5,
        max_header_list_size = 6,
    };
};

pub const Frame = struct {
    ty: Ty,
    flags: u8 = 0,
    stream: u31 = 0,
    settings: []const Setting,

    const big = std.builtin.Endian.big;

    const Ty = enum(u8) {
        data = 0,
        headers = 1,
        priority = 2,
        rst_stream = 3,
        settings = 4,
        push_promise = 5,
        ping = 6,
        goaway = 7,
        window_update = 8,
        continuation = 9,
    };

    pub fn init(ty: Ty, settings: []const Setting) @This() {
        return .{
            .ty = ty,
            .settings = settings,
        };
    }

    pub fn serialise(self: *const @This(), writer: *std.Io.Writer) !void {
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
