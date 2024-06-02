const Build = @import("std").Build;

pub fn build(b: *Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const executable = b.addExecutable(.{
        .name = "zig-wasi",
        .root_source_file = .{
            .src_path = .{
                .owner = b,
                .sub_path = "src/main.zig",
            },
        },
        .link_libc = true,
        .target = target,
        .optimize = optimize,
    });

    // b.default_step.dependOn(&executable.step);

    b.installArtifact(executable);
}
