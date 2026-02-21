const std = @import("std");

fn Child(comptime T: type) type {
    return struct { char: u8, node: ?*Node(T), value: ?T };
}

fn Node(comptime T: type) type {
    return struct {
        children: std.ArrayList(Child(T)),

        fn init() @This() {
            return .{ .children = std.ArrayList(Child(T)).empty };
        }
    };
}

pub fn Trie(comptime T: type) type {
    return struct {
        allocator: std.mem.Allocator,
        node: Node(T),

        pub fn init(allocator: std.mem.Allocator) @This() {
            return .{
                .allocator = allocator,
                .node = Node(T).init(),
            };
        }

        /// Retrieve value by key traversal
        pub fn search(self: *const @This(), key: []const u8) ?T {
            var node = &self.node;
            var remaining = key;

            // Protect against empty string
            while (remaining.len != 0) {
                for (node.children.items) |child| {
                    if (remaining[0] != child.char) continue;

                    // The deepest node found
                    if (remaining.len == 1) return child.value;

                    // Go Deeper
                    if (child.node) |n| {
                        node = n;
                        remaining = remaining[1..remaining.len];
                    } else {
                        // Travesesed as much of the key as possible but no
                        // deeper nodes exist
                        return null;
                    }
                }
            }
            return null;
        }

        /// Insert value in at key position
        pub fn insert(self: *@This(), key: []const u8, value: T) !void {
            var remaining = key;
            var node = &self.node;

            // Protect against empty string
            depth: while (remaining.len != 0) {
                for (node.children.items) |child| {
                    if (child.char != remaining[0]) continue;

                    std.log.debug("Found exisiting child\n", .{});
                    node = child.node.?;
                    remaining = remaining[1..remaining.len];
                    continue :depth;
                }

                // Last character in key
                if (remaining.len == 1) {
                    try node.children.append(self.allocator, .{
                        .char = remaining[0],
                        .node = null,
                        .value = value,
                    });
                    return;
                }

                // Go Deeper
                const new_node = try self.allocator.create(Node(T));
                new_node.* = Node(T).init();

                try node.children.append(self.allocator, .{
                    .char = remaining[0],
                    .node = new_node,
                    .value = value,
                });
                node = new_node;
                remaining = remaining[1..remaining.len];
            }
        }
    };
}

test "insert one" {
    var buffer: [1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buffer);
    const allocator = fba.allocator();

    var trie = Trie(u32).init(allocator);
    try trie.insert("c", 10);
    try std.testing.expect(trie.search("c") == 10);
}
test "insert cat" {
    var buffer: [1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buffer);
    const allocator = fba.allocator();

    var trie = Trie(u32).init(allocator);
    try trie.insert("cat", 10);
    try std.testing.expect(trie.search("cat") == 10);
}
test "insert none" {
    var buffer: [1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buffer);
    const allocator = fba.allocator();

    var trie = Trie(u32).init(allocator);
    try trie.insert("", 10);
    try std.testing.expect(trie.search("") == null);
}
test "insert cap cat" {
    var buffer: [1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buffer);
    const allocator = fba.allocator();

    var trie = Trie(u32).init(allocator);
    try trie.insert("cat", 10);
    try trie.insert("cap", 20);
    try std.testing.expect(trie.search("cap") == 20);
}
test "insert cap search caps" {
    var buffer: [1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buffer);
    const allocator = fba.allocator();

    var trie = Trie(u32).init(allocator);
    try trie.insert("cap", 20);
    try std.testing.expect(trie.search("caps") == null);
}
