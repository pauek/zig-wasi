const std = @import("std");
const assert = std.debug.assert;
const mem = std.mem;
const wasm = std.wasm;
const wasi = std.os.wasi;
const os = std.os;
const math = std.math;
const leb = std.leb;
const decode_log = std.log.scoped(.decode);
const stats_log = std.log.scoped(.stats);
const cpu_log = std.log.scoped(.cpu);
const func_log = std.log.scoped(.func);
const read_module = @import("./read_module.zig").read_module;
const VirtualMachine = @import("./vm.zig").VirtualMachine;

const max_memory = 3 * 1024 * 1024; // 3 MiB

pub export fn main(argc: c_int, argv: [*c][*:0]u8) c_int {
    _main(argv[0..@intCast(argc)]) catch |e| {
        std.debug.print("{s}\n", .{@errorName(e)});
    };
    return 1;
}

const ZigWasiError = error{
    WrongUsage,
};

fn _main(args: []const [*:0]const u8) !void {
    if (args.len < 2) {
        std.debug.print("Usage: zig-wasi <file.wasm>\n", .{});
        return ZigWasiError.WrongUsage;
    }

    var arena_instance = std.heap.ArenaAllocator.init(std.heap.raw_c_allocator);
    defer arena_instance.deinit();
    const arena = arena_instance.allocator();

    var vm: VirtualMachine = undefined;
    vm.memory = try arena.alloc(u8, max_memory);

    const wasm_file = args[1];

    const start_fn_idx = try read_module(arena, &vm, wasm_file);

    vm.stack = try arena.alloc(u32, 10000000);
    vm.stack_top = 0;
    vm.call(&vm.functions[start_fn_idx - @as(u32, @truncate(vm.imports.len))]);
    vm.run();
}
