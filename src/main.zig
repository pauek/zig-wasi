const std = @import("std");
const mem = std.mem;
const read_module = @import("./read_module.zig").read_module;
const vm = @import("./vm/vm.zig");

fn usage() void {
    std.debug.print("Usage: zig-wasi <file.wasm>\n", .{});
}

pub export fn main(argc: c_int, argv: [*c][*:0]u8) c_int {
    main_function(argv[0..@intCast(argc)]) catch |err| {
        switch (err) {
            ZigWasiError.WrongUsage => usage(),
            else => std.debug.print("{s}\n", .{@errorName(err)}),
        }
    };
    return 1;
}

const ZigWasiError = error{
    WrongUsage,
};

const ProgramArgs = struct { wasm_file: [*:0]const u8 };

fn parseArgs(main_args: []const [*:0]const u8) !ProgramArgs {
    var args: ProgramArgs = undefined;
    if (main_args.len < 2) {
        return ZigWasiError.WrongUsage;
    }
    args.wasm_file = main_args[1][0..];
    return args;
}

fn main_function(main_args: []const [*:0]const u8) !void {
    const args = try parseArgs(main_args);

    var arena_instance = std.heap.ArenaAllocator.init(std.heap.raw_c_allocator);
    defer arena_instance.deinit();
    const arena = arena_instance.allocator();

    var machine = try vm.makeVirtualMachine(arena);

    const start_fn_idx = try read_module(arena, &machine, args.wasm_file);

    machine.call(&machine.functions[start_fn_idx - @as(u32, @truncate(machine.imports.len))]);
    machine.run();
}
