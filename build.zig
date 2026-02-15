const std = @import("std");

pub fn build(b: *std.Build) void {
    const exe = b.addExecutable(.{
        .name = "httpz",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = b.graph.host,
        }),
    });
    exe.linkLibC();
    b.installArtifact(exe);

    const check = b.step("check", "For LSP");
    check.dependOn(&exe.step);

    const run = b.step("run", "Run the app");
    run.dependOn(&b.addRunArtifact(exe).step);
}
