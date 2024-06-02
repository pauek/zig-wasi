const std = @import("std");
const cReader = @import("io/c_reader.zig").cReader;
const assert = std.debug.assert;
const fs = std.fs;
const mem = std.mem;
const wasm = std.wasm;
const wasi = std.os.wasi;
const os = std.os;
const math = std.math;
const leb = std.leb;
const decode_log = std.log.scoped(.decode);
const stats_log = std.log.scoped(.stats);
const trace_log = std.log.scoped(.trace);
const cpu_log = std.log.scoped(.cpu);
const func_log = std.log.scoped(.func);

const SEEK = enum(c_int) { SET, CUR, END };
pub extern "c" fn fseek(stream: *std.c.FILE, offset: c_long, whence: SEEK) c_int;

pub fn log(
    comptime level: std.log.Level,
    comptime scope: @TypeOf(.EnumLiteral),
    comptime format: []const u8,
    args: anytype,
) void {
    if (scope == .decode) return;
    if (scope == .stats) return;
    if (scope == .cpu) return;
    if (scope == .trace) return;
    if (scope == .func) return;
    std.debug.print(format ++ "\n", args);
    _ = level;
}

const max_memory = 3 * 1024 * 1024; // 3 MiB

pub export fn main(argc: c_int, argv: [*c][*:0]u8) c_int {
    main2(argv[0..@intCast(argc)]) catch |e| {
        std.debug.print("{s}\n", .{@errorName(e)});
    };
    return 1;
}

fn main2(args: []const [*:0]const u8) !void {
    if (args.len < 2) {
        std.debug.print("Usage: zig-wasi <file.wasm>\n", .{});
        std.process.exit(1);
    }

    var arena_instance = std.heap.ArenaAllocator.init(std.heap.raw_c_allocator);
    defer arena_instance.deinit();
    const arena = arena_instance.allocator();

    var vm: VirtualMachine = undefined;
    vm.memory = try arena.alloc(u8, max_memory);

    const wasm_file = args[1];

    var start_fn_idx: u32 = undefined;
    var section_type: wasm.Section = undefined;
    {
        const module_file = std.c.fopen(wasm_file, "rb") orelse return error.FileNotFound;
        defer _ = std.c.fclose(module_file);
        const module_reader = cReader(module_file);

        var magic: [4]u8 = undefined;
        try module_reader.readNoEof(&magic);
        if (!mem.eql(u8, &magic, "\x00asm")) return error.NotWasm;

        const version = try module_reader.readVarInt(u32, std.builtin.Endian.little, 1);
        if (version != 1) return error.BadWasmVersion;

        section_type = @enumFromInt(try module_reader.readByte());
        while (section_type != .type)
            assert(fseek(module_file, @as(c_long, try leb.readULEB128(u32, module_reader)), .CUR) == 0);
        _ = try leb.readULEB128(u32, module_reader);

        var max_param_count: u64 = 0;
        vm.types = try arena.alloc(TypeInfo, try leb.readULEB128(u32, module_reader));
        for (vm.types) |*@"type"| {
            assert(try leb.readILEB128(i33, module_reader) == -0x20);

            @"type".param_count = try leb.readULEB128(u32, module_reader);
            assert(@"type".param_count <= 32);
            @"type".param_types = TypeInfo.ParamTypes.initEmpty();
            max_param_count = @max(@"type".param_count, max_param_count);
            var param_index: u32 = 0;
            while (param_index < @"type".param_count) : (param_index += 1) {
                const param_type = try leb.readILEB128(i33, module_reader);
                @"type".param_types.setValue(param_index, switch (param_type) {
                    -1, -3 => false,
                    -2, -4 => true,
                    else => unreachable,
                });
            }

            @"type".result_count = try leb.readULEB128(u32, module_reader);
            assert(@"type".result_count <= 1);
            @"type".result_types = TypeInfo.ResultTypes.initEmpty();
            var result_index: u32 = 0;
            while (result_index < @"type".result_count) : (result_index += 1) {
                const result_type = try leb.readILEB128(i33, module_reader);
                @"type".result_types.setValue(result_index, switch (result_type) {
                    -1, -3 => false,
                    -2, -4 => true,
                    else => unreachable,
                });
            }
        }

        section_type = @enumFromInt(try module_reader.readByte());
        while (section_type != .import)
            assert(fseek(module_file, @as(c_long, try leb.readULEB128(u32, module_reader)), .CUR) == 0);
        _ = try leb.readULEB128(u32, module_reader);

        {
            vm.imports = try arena.alloc(Import, try leb.readULEB128(u32, module_reader));

            comptime var max_str_len: usize = 0;
            inline for (.{ Import.Mod, Import.Name }) |Enum| {
                inline for (comptime std.meta.fieldNames(Enum)) |str| {
                    max_str_len = @max(str.len, max_str_len);
                }
            }
            var str_buf: [max_str_len]u8 = undefined;

            for (vm.imports) |*import| {
                const mod = str_buf[0..try leb.readULEB128(u32, module_reader)];
                try module_reader.readNoEof(mod);
                import.mod = std.meta.stringToEnum(Import.Mod, mod).?;

                const name = str_buf[0..try leb.readULEB128(u32, module_reader)];
                try module_reader.readNoEof(name);
                import.name = std.meta.stringToEnum(Import.Name, name).?;

                const kind: wasm.ExternalKind = @enumFromInt(try module_reader.readByte());
                const idx = try leb.readULEB128(u32, module_reader);
                switch (kind) {
                    .function => import.type_idx = idx,
                    .table, .memory, .global => unreachable,
                }
            }
        }

        section_type = @enumFromInt(try module_reader.readByte());
        while (section_type != .function)
            assert(fseek(module_file, @as(c_long, try leb.readULEB128(u32, module_reader)), .CUR) == 0);
        _ = try leb.readULEB128(u32, module_reader);

        vm.functions = try arena.alloc(Function, try leb.readULEB128(u32, module_reader));
        for (vm.functions, 0..) |*function, func_idx| {
            const len: u32 = @truncate(vm.imports.len);
            const idx: u32 = @truncate(func_idx);
            function.id = len + idx;
            function.type_idx = try leb.readULEB128(u32, module_reader);
        }

        section_type = @enumFromInt(try module_reader.readByte());
        while (section_type != .table)
            assert(fseek(module_file, @as(c_long, try leb.readULEB128(u32, module_reader)), .CUR) == 0);
        _ = try leb.readULEB128(u32, module_reader);

        {
            const table_count = try leb.readULEB128(u32, module_reader);
            if (table_count == 1) {
                assert(try leb.readILEB128(i33, module_reader) == -0x10);
                const limits_kind = try module_reader.readByte();
                vm.table = try arena.alloc(u32, try leb.readULEB128(u32, module_reader));
                switch (limits_kind) {
                    0x00 => {},
                    0x01 => _ = try leb.readULEB128(u32, module_reader),
                    else => unreachable,
                }
            } else assert(table_count == 0);
        }

        section_type = @enumFromInt(try module_reader.readByte());
        while (section_type != .memory)
            assert(fseek(module_file, @as(c_long, try leb.readULEB128(u32, module_reader)), .CUR) == 0);
        _ = try leb.readULEB128(u32, module_reader);

        {
            assert(try leb.readULEB128(u32, module_reader) == 1);
            const limits_kind = try module_reader.readByte();
            vm.memory_len = try leb.readULEB128(u32, module_reader) * wasm.page_size;
            switch (limits_kind) {
                0x00 => {},
                0x01 => _ = try leb.readULEB128(u32, module_reader),
                else => unreachable,
            }
        }

        section_type = @enumFromInt(try module_reader.readByte());
        while (section_type != .global)
            assert(fseek(module_file, @as(c_long, try leb.readULEB128(u32, module_reader)), .CUR) == 0);
        _ = try leb.readULEB128(u32, module_reader);

        vm.globals = try arena.alloc(u32, try leb.readULEB128(u32, module_reader));
        for (vm.globals) |*global| {
            assert(try leb.readILEB128(i33, module_reader) == -1);
            _ = try module_reader.readByte();
            const global_type: wasm.Opcode = @enumFromInt(try module_reader.readByte());
            assert(global_type == .i32_const);
            global.* = @intCast(try leb.readILEB128(i32, module_reader));
            const opcode: wasm.Opcode = @enumFromInt(try module_reader.readByte());
            assert(opcode == .end);
        }

        section_type = @enumFromInt(try module_reader.readByte());
        while (section_type != .@"export")
            assert(fseek(module_file, @as(c_long, try leb.readULEB128(u32, module_reader)), .CUR) == 0);
        _ = try leb.readULEB128(u32, module_reader);

        {
            var found_start_fn = false;
            const start_name = "_start";
            var str_buf: [start_name.len]u8 = undefined;

            var export_count = try leb.readULEB128(u32, module_reader);
            while (export_count > 0) : (export_count -= 1) {
                const name_len = try leb.readULEB128(u32, module_reader);
                var is_start_fn = false;
                if (name_len == start_name.len) {
                    try module_reader.readNoEof(&str_buf);
                    is_start_fn = mem.eql(u8, &str_buf, start_name);
                    found_start_fn = found_start_fn or is_start_fn;
                } else assert(fseek(module_file, @as(c_long, name_len), .CUR) == 0);

                const kind: wasm.ExternalKind = @enumFromInt(try module_reader.readByte());
                const idx = try leb.readULEB128(u32, module_reader);
                switch (kind) {
                    .function => if (is_start_fn) {
                        start_fn_idx = idx;
                    },
                    .table, .memory, .global => {},
                }
            }
            assert(found_start_fn);
        }

        section_type = @enumFromInt(try module_reader.readByte());
        while (section_type != .element)
            assert(fseek(module_file, @as(c_long, try leb.readULEB128(u32, module_reader)), .CUR) == 0);
        _ = try leb.readULEB128(u32, module_reader);

        {
            var segment_count = try leb.readULEB128(u32, module_reader);
            while (segment_count > 0) : (segment_count -= 1) {
                const flags: u32 = @intCast(try leb.readULEB128(u32, module_reader));
                assert(flags & 0b001 == 0b000);
                if (flags & 0b010 == 0b010) assert(try leb.readULEB128(u32, module_reader) == 0);

                const opcode: wasm.Opcode = @enumFromInt(try module_reader.readByte());
                assert(opcode == .i32_const);
                var offset: u32 = @intCast(try leb.readILEB128(i32, module_reader));
                const end: wasm.Opcode = @enumFromInt(try module_reader.readByte());
                assert(end == .end);

                const element_type = if (flags & 0b110 != 0b110) idx: {
                    if (flags & 0b010 == 0b010) assert(try module_reader.readByte() == 0x00);
                    break :idx -0x10;
                } else try leb.readILEB128(i33, module_reader);
                assert(element_type == -0x10);

                var element_count = try leb.readULEB128(u32, module_reader);
                while (element_count > 0) : ({
                    offset += 1;
                    element_count -= 1;
                }) {
                    if (flags & 0b010 == 0b010)
                        assert(try module_reader.readByte() == 0xD2);
                    vm.table[offset] = try leb.readULEB128(u32, module_reader);
                    if (flags & 0b010 == 0b010) {
                        const end_opcode: wasm.Opcode = @enumFromInt(try module_reader.readByte());
                        assert(end_opcode == .end);
                    }
                }
            }
        }

        section_type = @enumFromInt(try module_reader.readByte());
        while (section_type != .code)
            assert(fseek(module_file, @as(c_long, try leb.readULEB128(u32, module_reader)), .CUR) == 0);
        _ = try leb.readULEB128(u32, module_reader);

        var max_frame_size: u64 = 0;
        {
            vm.opcodes = try arena.alloc(u8, 5000000);
            vm.operands = try arena.alloc(u32, 5000000);

            assert(try leb.readULEB128(u32, module_reader) == vm.functions.len);
            var pc = ProgramCounter{ .opcode = 0, .operand = 0 };
            var stack: StackInfo = undefined;
            for (vm.functions) |*func| {
                _ = try leb.readULEB128(u32, module_reader);

                stack = .{};
                const type_info = vm.types[func.type_idx];
                var param_i: u32 = 0;
                while (param_i < type_info.param_count) : (param_i += 1) {
                    const entry_type: StackInfo.EntryType = @enumFromInt(
                        @intFromBool(type_info.param_types.isSet(param_i)),
                    );
                    stack.push(entry_type);
                }
                const params_size = stack.top_offset;

                var local_sets_count = try leb.readULEB128(u32, module_reader);
                while (local_sets_count > 0) : (local_sets_count -= 1) {
                    var local_set_count = try leb.readULEB128(u32, module_reader);
                    const local_type = switch (try leb.readILEB128(i33, module_reader)) {
                        -1, -3 => StackInfo.EntryType.i32,
                        -2, -4 => StackInfo.EntryType.i64,
                        else => unreachable,
                    };
                    while (local_set_count > 0) : (local_set_count -= 1)
                        stack.push(local_type);
                }
                func.locals_size = stack.top_offset - params_size;
                max_frame_size = @max(params_size + func.locals_size, max_frame_size);

                func.entry_pc = pc;
                decode_log.debug("decoding func id {d} with pc {d}:{d}", .{ func.id, pc.opcode, pc.operand });
                try vm.decodeCode(module_reader, type_info, &pc, &stack);
            }

            var opcode_counts = [1]u64{0} ** 0x100;
            var prefix: ?Opcode = null;
            for (vm.opcodes[0..pc.opcode]) |opcode| {
                if (prefix) |pre| {
                    switch (pre) {
                        else => unreachable,
                    }
                    prefix = null;
                } else {
                    opcode_counts[opcode] += 1;
                }
            }

            stats_log.debug("{} opcodes", .{pc.opcode});
            stats_log.debug("{} operands", .{pc.operand});
            for (opcode_counts, 0..) |opcode_count, opcode| {
                const last_opcode: usize = @intFromEnum(Opcode.last);
                if (opcode > last_opcode) continue;
                const opcode_enum: Opcode = @enumFromInt(opcode);
                stats_log.debug("{} {s}", .{ opcode_count, @tagName(opcode_enum) });
            }
            stats_log.debug("{} zero offsets", .{offset_counts[0]});
            stats_log.debug("{} non-zero offsets", .{offset_counts[1]});
            stats_log.debug("{} max offset", .{max_offset});
            stats_log.debug("{} max label depth", .{max_label_depth});
            stats_log.debug("{} max frame size", .{max_frame_size});
            stats_log.debug("{} max param count", .{max_param_count});
        }

        section_type = @enumFromInt(try module_reader.readByte());
        while (section_type != .data)
            assert(fseek(module_file, @as(c_long, try leb.readULEB128(u32, module_reader)), .CUR) == 0);
        _ = try leb.readULEB128(u32, module_reader);

        {
            var segment_count = try leb.readULEB128(u32, module_reader);
            while (segment_count > 0) : (segment_count -= 1) {
                const flags = @as(u32, try leb.readULEB128(u32, module_reader));
                assert(flags & 0b001 == 0b000);
                if (flags & 0b010 == 0b010) assert(try leb.readULEB128(u32, module_reader) == 0);

                const i32_const: wasm.Opcode = @enumFromInt(try module_reader.readByte());
                assert(i32_const == .i32_const);

                const offset = @as(u32, @bitCast(try leb.readILEB128(i32, module_reader)));
                const end: wasm.Opcode = @enumFromInt(try module_reader.readByte());
                assert(end == .end);

                const length = try leb.readULEB128(u32, module_reader);
                try module_reader.readNoEof(vm.memory[offset..][0..length]);
            }
        }
    }

    vm.stack = try arena.alloc(u32, 10000000);
    vm.stack_top = 0;
    vm.call(&vm.functions[start_fn_idx - @as(u32, @truncate(vm.imports.len))]);
    vm.run();
}

const Opcode = enum {
    @"unreachable",
    br_void,
    br_32,
    br_64,
    br_nez_void,
    br_nez_32,
    br_nez_64,
    br_eqz_void,
    br_eqz_32,
    br_eqz_64,
    br_table_void,
    br_table_32,
    br_table_64,
    return_void,
    return_32,
    return_64,
    call_import,
    call_func,
    call_indirect,
    drop_32,
    drop_64,
    select_32,
    select_64,
    local_get_32,
    local_get_64,
    local_set_32,
    local_set_64,
    local_tee_32,
    local_tee_64,
    global_get_0_32,
    global_get_32,
    global_set_0_32,
    global_set_32,
    load_0_8,
    load_8,
    load_0_16,
    load_16,
    load_0_32,
    load_32,
    load_0_64,
    load_64,
    store_0_8,
    store_8,
    store_0_16,
    store_16,
    store_0_32,
    store_32,
    store_0_64,
    store_64,
    mem_size,
    mem_grow,
    const_0_32,
    const_0_64,
    const_1_32,
    const_1_64,
    const_32,
    const_64,
    const_umax_32,
    const_umax_64,
    eqz_32,
    eq_32,
    ne_32,
    slt_32,
    ult_32,
    sgt_32,
    ugt_32,
    sle_32,
    ule_32,
    sge_32,
    uge_32,
    eqz_64,
    eq_64,
    ne_64,
    slt_64,
    ult_64,
    sgt_64,
    ugt_64,
    sle_64,
    ule_64,
    sge_64,
    uge_64,
    feq_32,
    fne_32,
    flt_32,
    fgt_32,
    fle_32,
    fge_32,
    feq_64,
    fne_64,
    flt_64,
    fgt_64,
    fle_64,
    fge_64,
    clz_32,
    ctz_32,
    popcnt_32,
    add_32,
    sub_32,
    mul_32,
    sdiv_32,
    udiv_32,
    srem_32,
    urem_32,
    and_32,
    or_32,
    xor_32,
    shl_32,
    ashr_32,
    lshr_32,
    rol_32,
    ror_32,
    clz_64,
    ctz_64,
    popcnt_64,
    add_64,
    sub_64,
    mul_64,
    sdiv_64,
    udiv_64,
    srem_64,
    urem_64,
    and_64,
    or_64,
    xor_64,
    shl_64,
    ashr_64,
    lshr_64,
    rol_64,
    ror_64,
    fabs_32,
    fneg_32,
    ceil_32,
    floor_32,
    trunc_32,
    nearest_32,
    sqrt_32,
    fadd_32,
    fsub_32,
    fmul_32,
    fdiv_32,
    fmin_32,
    fmax_32,
    copysign_32,
    fabs_64,
    fneg_64,
    ceil_64,
    floor_64,
    trunc_64,
    nearest_64,
    sqrt_64,
    fadd_64,
    fsub_64,
    fmul_64,
    fdiv_64,
    fmin_64,
    fmax_64,
    copysign_64,
    ftos_32_32,
    ftou_32_32,
    ftos_32_64,
    ftou_32_64,
    sext_64_32,
    ftos_64_32,
    ftou_64_32,
    ftos_64_64,
    ftou_64_64,
    stof_32_32,
    utof_32_32,
    stof_32_64,
    utof_32_64,
    ftof_32_64,
    stof_64_32,
    utof_64_32,
    stof_64_64,
    utof_64_64,
    ftof_64_32,
    sext8_32,
    sext16_32,
    sext8_64,
    sext16_64,
    sext32_64,
    memcpy,
    memset,

    const wrap_32_64 = Opcode.drop_32;
    const zext_64_32 = Opcode.const_0_32;
    const last = Opcode.memset;
};

var offset_counts = [2]u64{ 0, 0 };
var max_offset: u64 = 0;

var max_label_depth: u64 = 0;

const ProgramCounter = struct { opcode: u32, operand: u32 };

const Mutability = enum { @"const", @"var" };

const TypeInfo = struct {
    const ParamTypes = std.StaticBitSet(1 << 5);
    const ResultTypes = std.StaticBitSet(1);

    param_count: u32,
    param_types: ParamTypes,
    result_count: u32,
    result_types: ResultTypes,
};

const Function = struct {
    id: u32,
    entry_pc: ProgramCounter,
    type_idx: u32,
    locals_size: u32,
};

const Import = struct {
    const Mod = enum {
        wasi_snapshot_preview1,
    };
    const Name = enum {
        args_get,
        args_sizes_get,
        clock_time_get,
        debug,
        debug_slice,
        environ_get,
        environ_sizes_get,
        fd_close,
        fd_fdstat_get,
        fd_filestat_get,
        fd_filestat_set_size,
        fd_filestat_set_times,
        fd_pread,
        fd_prestat_dir_name,
        fd_prestat_get,
        fd_pwrite,
        fd_read,
        fd_readdir,
        fd_write,
        path_create_directory,
        path_filestat_get,
        path_open,
        path_remove_directory,
        path_rename,
        path_unlink_file,
        proc_exit,
        random_get,
    };

    mod: Mod,
    name: Name,
    type_idx: u32,
};

const Label = struct {
    opcode: wasm.Opcode,
    stack_index: u32,
    stack_offset: u32,
    type_info: TypeInfo,
    // this is a maxInt terminated linked list that is stored in the operands array
    ref_list: u32 = math.maxInt(u32),
    extra: union {
        loop_pc: ProgramCounter,
        else_ref: u32,
    } = undefined,

    fn operandCount(self: Label) u32 {
        return if (self.opcode == .loop) self.type_info.param_count else self.type_info.result_count;
    }

    fn operandType(self: Label, index: u32) StackInfo.EntryType {
        return StackInfo.EntryType.fromBool(if (self.opcode == .loop)
            self.type_info.param_types.isSet(index)
        else
            self.type_info.result_types.isSet(index));
    }
};

const StackInfo = struct {
    // f32 is stored as i32 and f64 is stored as i64
    const EntryType = enum {
        i32,
        i64,

        fn size(self: EntryType) u32 {
            return switch (self) {
                .i32 => 1,
                .i64 => 2,
            };
        }

        fn toBool(self: EntryType) bool {
            return self != .i32;
        }

        fn fromBool(self: bool) EntryType {
            return @enumFromInt(@intFromBool(self));
        }
    };
    const max_stack_depth = 1 << 12;

    top_index: u32 = 0,
    top_offset: u32 = 0,
    types: std.StaticBitSet(max_stack_depth) = undefined,
    offsets: [max_stack_depth]u32 = undefined,

    fn push(self: *StackInfo, entry_type: EntryType) void {
        self.types.setValue(self.top_index, entry_type.toBool());
        self.offsets[self.top_index] = self.top_offset;
        self.top_index += 1;
        self.top_offset += entry_type.size();
    }

    fn pop(self: *StackInfo, entry_type: EntryType) void {
        assert(self.top() == entry_type);
        self.top_index -= 1;
        self.top_offset -= entry_type.size();
        assert(self.top_offset == self.offsets[self.top_index]);
    }

    fn top(self: StackInfo) EntryType {
        return EntryType.fromBool(self.types.isSet(self.top_index - 1));
    }

    fn local(self: StackInfo, local_idx: u32) EntryType {
        return EntryType.fromBool(self.types.isSet(local_idx));
    }
};

const VirtualMachine = struct {
    stack: []u32,
    /// Points to one after the last stack item.
    stack_top: u32,
    pc: ProgramCounter,
    memory_len: u32,
    opcodes: []u8,
    operands: []u32,
    functions: []Function,
    types: []TypeInfo,
    globals: []u32,
    memory: []u8,
    imports: []Import,
    args: []const [*:0]const u8,
    table: []u32,

    fn decodeCode(
        vm: *VirtualMachine,
        reader: anytype,
        func_type_info: TypeInfo,
        pc: *ProgramCounter,
        stack: *StackInfo,
    ) !void {
        const opcodes = vm.opcodes;
        const operands = vm.operands;

        // push return address
        const frame_size = stack.top_offset;
        stack.push(.i32);
        stack.push(.i32);

        var unreachable_depth: u32 = 0;
        var label_i: u32 = 0;
        var labels: [1 << 9]Label = undefined;
        labels[label_i] = .{
            .opcode = .block,
            .stack_index = stack.top_index,
            .stack_offset = stack.top_offset,
            .type_info = func_type_info,
        };

        var state: enum { default, bool_not } = .default;

        while (true) {
            assert(stack.top_index >= labels[0].stack_index);
            assert(stack.top_offset >= labels[0].stack_offset);
            const opcode_byte = try reader.readByte();
            const opcode_enum: wasm.Opcode = @enumFromInt(opcode_byte);
            const prefixed_opcode: u8 = if (opcode_enum == .misc_prefix)
                @truncate(try leb.readULEB128(u32, reader))
            else
                undefined;

            //decode_log.debug("stack.top_index = {}, stack.top_offset = {}, opcode = {s}, prefixed_opcode = {s}", .{
            //    stack.top_index,
            //    stack.top_offset,
            //    @tagName(@enumFromInt(wasm.Opcode, opcode)),
            //    if (@enumFromInt(wasm.Opcode, opcode) == .prefixed)
            //        @tagName(@enumFromInt(wasm.PrefixedOpcode, prefixed_opcode))
            //    else
            //        "(none)",
            //});

            decode_log.debug("decodeCode opcode=0x{x} pc={d}:{d}", .{ opcode_byte, pc.opcode, pc.operand });
            const old_pc = pc.*;
            const prefixed_enum: wasm.MiscOpcode = @enumFromInt(prefixed_opcode);

            if (unreachable_depth == 0) switch (opcode_enum) {
                .@"unreachable",
                .nop,
                .block,
                .loop,
                .@"else",
                .end,
                .br,
                .@"return",
                .call,
                .local_get,
                .local_set,
                .local_tee,
                .global_get,
                .global_set,
                .drop,
                .select,
                => {}, // handled manually below

                .@"if",
                .br_if,
                .br_table,
                .call_indirect,
                => stack.pop(.i32),

                .memory_size,
                .i32_const,
                .f32_const,
                => stack.push(.i32),

                .i64_const,
                .f64_const,
                => stack.push(.i64),

                .i32_load,
                .f32_load,
                .i32_load8_s,
                .i32_load8_u,
                .i32_load16_s,
                .i32_load16_u,
                => {
                    stack.pop(.i32);
                    stack.push(.i32);
                },

                .i64_load,
                .f64_load,
                .i64_load8_s,
                .i64_load8_u,
                .i64_load16_s,
                .i64_load16_u,
                .i64_load32_s,
                .i64_load32_u,
                => {
                    stack.pop(.i32);
                    stack.push(.i64);
                },

                .memory_grow,
                .i32_eqz,
                .i32_clz,
                .i32_ctz,
                .i32_popcnt,
                .f32_abs,
                .f32_neg,
                .f32_ceil,
                .f32_floor,
                .f32_trunc,
                .f32_nearest,
                .f32_sqrt,
                .i32_trunc_f32_s,
                .i32_trunc_f32_u,
                .f32_convert_i32_s,
                .f32_convert_i32_u,
                .i32_reinterpret_f32,
                .f32_reinterpret_i32,
                .i32_extend8_s,
                .i32_extend16_s,
                => {
                    stack.pop(.i32);
                    stack.push(.i32);
                },

                .i64_eqz,
                .i32_wrap_i64,
                .i32_trunc_f64_s,
                .i32_trunc_f64_u,
                .f32_convert_i64_s,
                .f32_convert_i64_u,
                .f32_demote_f64,
                => {
                    stack.pop(.i64);
                    stack.push(.i32);
                },

                .i64_clz,
                .i64_ctz,
                .i64_popcnt,
                .f64_abs,
                .f64_neg,
                .f64_ceil,
                .f64_floor,
                .f64_trunc,
                .f64_nearest,
                .f64_sqrt,
                .i64_trunc_f64_s,
                .i64_trunc_f64_u,
                .f64_convert_i64_s,
                .f64_convert_i64_u,
                .i64_reinterpret_f64,
                .f64_reinterpret_i64,
                .i64_extend8_s,
                .i64_extend16_s,
                .i64_extend32_s,
                => {
                    stack.pop(.i64);
                    stack.push(.i64);
                },

                .i64_extend_i32_s,
                .i64_extend_i32_u,
                .i64_trunc_f32_s,
                .i64_trunc_f32_u,
                .f64_convert_i32_s,
                .f64_convert_i32_u,
                .f64_promote_f32,
                => {
                    stack.pop(.i32);
                    stack.push(.i64);
                },

                .i32_store,
                .f32_store,
                .i32_store8,
                .i32_store16,
                => {
                    stack.pop(.i32);
                    stack.pop(.i32);
                },

                .i64_store,
                .f64_store,
                .i64_store8,
                .i64_store16,
                .i64_store32,
                => {
                    stack.pop(.i64);
                    stack.pop(.i32);
                },

                .i32_eq,
                .i32_ne,
                .i32_lt_s,
                .i32_lt_u,
                .i32_gt_s,
                .i32_gt_u,
                .i32_le_s,
                .i32_le_u,
                .i32_ge_s,
                .i32_ge_u,
                .f32_eq,
                .f32_ne,
                .f32_lt,
                .f32_gt,
                .f32_le,
                .f32_ge,
                => {
                    stack.pop(.i32);
                    stack.pop(.i32);
                    stack.push(.i32);
                },

                .i64_eq,
                .i64_ne,
                .i64_lt_s,
                .i64_lt_u,
                .i64_gt_s,
                .i64_gt_u,
                .i64_le_s,
                .i64_le_u,
                .i64_ge_s,
                .i64_ge_u,
                .f64_eq,
                .f64_ne,
                .f64_lt,
                .f64_gt,
                .f64_le,
                .f64_ge,
                => {
                    stack.pop(.i64);
                    stack.pop(.i64);
                    stack.push(.i32);
                },

                .i32_add,
                .i32_sub,
                .i32_mul,
                .i32_div_s,
                .i32_div_u,
                .i32_rem_s,
                .i32_rem_u,
                .i32_and,
                .i32_or,
                .i32_xor,
                .i32_shl,
                .i32_shr_s,
                .i32_shr_u,
                .i32_rotl,
                .i32_rotr,
                .f32_add,
                .f32_sub,
                .f32_mul,
                .f32_div,
                .f32_min,
                .f32_max,
                .f32_copysign,
                => {
                    stack.pop(.i32);
                    stack.pop(.i32);
                    stack.push(.i32);
                },

                .i64_add,
                .i64_sub,
                .i64_mul,
                .i64_div_s,
                .i64_div_u,
                .i64_rem_s,
                .i64_rem_u,
                .i64_and,
                .i64_or,
                .i64_xor,
                .i64_shl,
                .i64_shr_s,
                .i64_shr_u,
                .i64_rotl,
                .i64_rotr,
                .f64_add,
                .f64_sub,
                .f64_mul,
                .f64_div,
                .f64_min,
                .f64_max,
                .f64_copysign,
                => {
                    stack.pop(.i64);
                    stack.pop(.i64);
                    stack.push(.i64);
                },

                .misc_prefix => switch (prefixed_enum) {
                    .i32_trunc_sat_f32_s,
                    .i32_trunc_sat_f32_u,
                    => {
                        stack.pop(.i32);
                        stack.push(.i32);
                    },

                    .i32_trunc_sat_f64_s,
                    .i32_trunc_sat_f64_u,
                    => {
                        stack.pop(.i64);
                        stack.push(.i32);
                    },

                    .i64_trunc_sat_f32_s,
                    .i64_trunc_sat_f32_u,
                    => {
                        stack.pop(.i32);
                        stack.push(.i64);
                    },

                    .i64_trunc_sat_f64_s,
                    .i64_trunc_sat_f64_u,
                    => {
                        stack.pop(.i64);
                        stack.push(.i64);
                    },

                    .memory_init,
                    .memory_copy,
                    .memory_fill,
                    .table_init,
                    .table_copy,
                    => {
                        stack.pop(.i32);
                        stack.pop(.i32);
                        stack.pop(.i32);
                    },

                    .table_fill => {
                        stack.pop(.i32);
                        stack.pop(unreachable);
                        stack.pop(.i32);
                    },

                    .data_drop,
                    .elem_drop,
                    => {},

                    .table_grow => {
                        stack.pop(.i32);
                        stack.pop(unreachable);
                        stack.push(.i32);
                    },

                    .table_size => stack.push(.i32),

                    _ => unreachable,
                },

                .simd_prefix => unreachable,
                .atomics_prefix => unreachable,
                _ => unreachable,
            };
            switch (opcode_enum) {
                .@"unreachable" => if (unreachable_depth == 0) {
                    opcodes[pc.opcode] = @intFromEnum(Opcode.@"unreachable");
                    pc.opcode += 1;
                    unreachable_depth += 1;
                },
                .nop,
                .i32_reinterpret_f32,
                .i64_reinterpret_f64,
                .f32_reinterpret_i32,
                .f64_reinterpret_i64,
                => {},
                .block, .loop, .@"if" => |opc| {
                    const block_type = try leb.readILEB128(i33, reader);
                    if (unreachable_depth == 0) {
                        label_i += 1;
                        max_label_depth = @max(label_i, max_label_depth);
                        const label = &labels[label_i];
                        const type_info = if (block_type < 0) TypeInfo{
                            .param_count = 0,
                            .param_types = TypeInfo.ParamTypes.initEmpty(),
                            .result_count = @intFromBool(block_type != -0x40),
                            .result_types = switch (block_type) {
                                -0x40, -1, -3 => TypeInfo.ResultTypes.initEmpty(),
                                -2, -4 => TypeInfo.ResultTypes.initFull(),
                                else => unreachable,
                            },
                        } else vm.types[@intCast(block_type)];

                        var param_i = type_info.param_count;
                        while (param_i > 0) {
                            param_i -= 1;
                            stack.pop(StackInfo.EntryType.fromBool(
                                type_info.param_types.isSet(param_i),
                            ));
                        }
                        label.* = .{
                            .opcode = opc,
                            .stack_index = stack.top_index,
                            .stack_offset = stack.top_offset,
                            .type_info = type_info,
                        };
                        while (param_i < type_info.param_count) : (param_i += 1)
                            stack.push(StackInfo.EntryType.fromBool(
                                type_info.param_types.isSet(param_i),
                            ));

                        switch (opc) {
                            .block => {},
                            .loop => {
                                label.extra = .{ .loop_pc = pc.* };
                            },
                            .@"if" => {
                                const bool_not = state == .bool_not;
                                if (bool_not) pc.opcode -= 1;
                                opcodes[pc.opcode] = @intFromEnum(if (bool_not)
                                    Opcode.br_nez_void
                                else
                                    Opcode.br_eqz_void);
                                pc.opcode += 1;
                                operands[pc.operand] = 0;
                                label.extra = .{ .else_ref = pc.operand + 1 };
                                pc.operand += 3;
                            },
                            else => unreachable,
                        }
                    } else unreachable_depth += 1;
                },
                .@"else" => if (unreachable_depth <= 1) {
                    const label = &labels[label_i];
                    assert(label.opcode == .@"if");
                    label.opcode = .@"else";

                    if (unreachable_depth == 0) {
                        const operand_count = label.operandCount();
                        var operand_i = operand_count;
                        while (operand_i > 0) {
                            operand_i -= 1;
                            stack.pop(label.operandType(operand_i));
                        }
                        assert(stack.top_index == label.stack_index);
                        assert(stack.top_offset == label.stack_offset);

                        opcodes[pc.opcode] = @intFromEnum(switch (operand_count) {
                            0 => Opcode.br_void,
                            1 => switch (label.operandType(0)) {
                                .i32 => Opcode.br_32,
                                .i64 => Opcode.br_64,
                            },
                            else => unreachable,
                        });
                        pc.opcode += 1;
                        operands[pc.operand + 0] = stack.top_offset - label.stack_offset;
                        operands[pc.operand + 1] = label.ref_list;
                        label.ref_list = pc.operand + 1;
                        pc.operand += 3;
                    } else unreachable_depth = 0;

                    operands[label.extra.else_ref + 0] = pc.opcode;
                    operands[label.extra.else_ref + 1] = pc.operand;
                    label.extra = undefined;

                    stack.top_index = label.stack_index;
                    stack.top_offset = label.stack_offset;
                    var param_i: u32 = 0;
                    while (param_i < label.type_info.param_count) : (param_i += 1)
                        stack.push(StackInfo.EntryType.fromBool(
                            label.type_info.param_types.isSet(param_i),
                        ));
                },
                .end => {
                    if (unreachable_depth <= 1) {
                        const label = &labels[label_i];
                        const target_pc = if (label.opcode == .loop) &label.extra.loop_pc else pc;
                        if (label.opcode == .@"if") {
                            operands[label.extra.else_ref + 0] = target_pc.opcode;
                            operands[label.extra.else_ref + 1] = target_pc.operand;
                            label.extra = undefined;
                        }
                        var ref = label.ref_list;
                        while (ref != math.maxInt(u32)) {
                            const next_ref = operands[ref];
                            operands[ref + 0] = target_pc.opcode;
                            operands[ref + 1] = target_pc.operand;
                            ref = next_ref;
                        }

                        if (unreachable_depth == 0) {
                            var result_i = label.type_info.result_count;
                            while (result_i > 0) {
                                result_i -= 1;
                                stack.pop(StackInfo.EntryType.fromBool(
                                    label.type_info.result_types.isSet(result_i),
                                ));
                            }
                        } else unreachable_depth = 0;

                        if (label_i == 0) {
                            assert(stack.top_index == label.stack_index);
                            assert(stack.top_offset == label.stack_offset);

                            opcodes[pc.opcode] = @intFromEnum(switch (labels[0].type_info.result_count) {
                                0 => Opcode.return_void,
                                1 => switch (StackInfo.EntryType.fromBool(
                                    labels[0].type_info.result_types.isSet(0),
                                )) {
                                    .i32 => Opcode.return_32,
                                    .i64 => Opcode.return_64,
                                },
                                else => unreachable,
                            });
                            pc.opcode += 1;
                            operands[pc.operand + 0] = stack.top_offset - labels[0].stack_offset;
                            operands[pc.operand + 1] = frame_size;
                            pc.operand += 2;
                            return;
                        }
                        label_i -= 1;

                        stack.top_index = label.stack_index;
                        stack.top_offset = label.stack_offset;
                        var result_i: u32 = 0;
                        while (result_i < label.type_info.result_count) : (result_i += 1)
                            stack.push(StackInfo.EntryType.fromBool(
                                label.type_info.result_types.isSet(result_i),
                            ));
                    } else unreachable_depth -= 1;
                },
                .br,
                .br_if,
                => |opc| {
                    const label_idx = try leb.readULEB128(u32, reader);
                    if (unreachable_depth == 0) {
                        const label = &labels[label_i - label_idx];
                        const operand_count = label.operandCount();
                        var operand_i = operand_count;
                        while (operand_i > 0) {
                            operand_i -= 1;
                            stack.pop(label.operandType(operand_i));
                        }

                        const bool_not = state == .bool_not and opc == .br_if;
                        if (bool_not) pc.opcode -= 1;
                        opcodes[pc.opcode] = @intFromEnum(switch (opc) {
                            .br => switch (operand_count) {
                                0 => Opcode.br_void,
                                1 => switch (label.operandType(0)) {
                                    .i32 => Opcode.br_32,
                                    .i64 => Opcode.br_64,
                                },
                                else => unreachable,
                            },
                            .br_if => switch (label.type_info.result_count) {
                                0 => if (bool_not) Opcode.br_eqz_void else Opcode.br_nez_void,
                                1 => switch (label.operandType(0)) {
                                    .i32 => if (bool_not) Opcode.br_eqz_32 else Opcode.br_nez_32,
                                    .i64 => if (bool_not) Opcode.br_eqz_64 else Opcode.br_nez_64,
                                },
                                else => unreachable,
                            },
                            else => unreachable,
                        });
                        pc.opcode += 1;
                        operands[pc.operand + 0] = stack.top_offset - label.stack_offset;
                        operands[pc.operand + 1] = label.ref_list;
                        label.ref_list = pc.operand + 1;
                        pc.operand += 3;

                        switch (opc) {
                            .br => unreachable_depth += 1,
                            .br_if => while (operand_i < operand_count) : (operand_i += 1)
                                stack.push(label.operandType(operand_i)),
                            else => unreachable,
                        }
                    }
                },
                .br_table => {
                    const labels_len = try leb.readULEB128(u32, reader);
                    var i: u32 = 0;
                    while (i <= labels_len) : (i += 1) {
                        const label_idx = try leb.readULEB128(u32, reader);
                        if (unreachable_depth != 0) continue;
                        const label = &labels[label_i - label_idx];
                        if (i == 0) {
                            const operand_count = label.operandCount();
                            var operand_i = operand_count;
                            while (operand_i > 0) {
                                operand_i -= 1;
                                stack.pop(label.operandType(operand_i));
                            }

                            opcodes[pc.opcode] = @intFromEnum(switch (operand_count) {
                                0 => Opcode.br_table_void,
                                1 => switch (label.operandType(0)) {
                                    .i32 => Opcode.br_table_32,
                                    .i64 => Opcode.br_table_64,
                                },
                                else => unreachable,
                            });
                            pc.opcode += 1;
                            operands[pc.operand] = labels_len;
                            pc.operand += 1;
                        }
                        operands[pc.operand + 0] = stack.top_offset - label.stack_offset;
                        operands[pc.operand + 1] = label.ref_list;
                        label.ref_list = pc.operand + 1;
                        pc.operand += 3;
                    }
                    if (unreachable_depth == 0) unreachable_depth += 1;
                },
                .@"return" => if (unreachable_depth == 0) {
                    var result_i = labels[0].type_info.result_count;
                    while (result_i > 0) {
                        result_i -= 1;
                        stack.pop(StackInfo.EntryType.fromBool(
                            labels[0].type_info.result_types.isSet(result_i),
                        ));
                    }

                    opcodes[pc.opcode] = @intFromEnum(switch (labels[0].type_info.result_count) {
                        0 => Opcode.return_void,
                        1 => switch (StackInfo.EntryType.fromBool(
                            labels[0].type_info.result_types.isSet(0),
                        )) {
                            .i32 => Opcode.return_32,
                            .i64 => Opcode.return_64,
                        },
                        else => unreachable,
                    });
                    pc.opcode += 1;
                    operands[pc.operand + 0] = stack.top_offset - labels[0].stack_offset;
                    operands[pc.operand + 1] = frame_size;
                    pc.operand += 2;
                    unreachable_depth += 1;
                },
                .call => {
                    const fn_id = try leb.readULEB128(u32, reader);
                    if (unreachable_depth == 0) {
                        const type_info = &vm.types[
                            if (fn_id < vm.imports.len) type_idx: {
                                opcodes[pc.opcode + 0] = @intFromEnum(Opcode.call_import);
                                opcodes[pc.opcode + 1] = @truncate(fn_id);
                                pc.opcode += 2;
                                break :type_idx vm.imports[fn_id].type_idx;
                            } else type_idx: {
                                const fn_idx = fn_id - @as(u32, @truncate(vm.imports.len));
                                opcodes[pc.opcode] = @intFromEnum(Opcode.call_func);
                                pc.opcode += 1;
                                operands[pc.operand] = fn_idx;
                                pc.operand += 1;
                                break :type_idx vm.functions[fn_idx].type_idx;
                            }
                        ];

                        var param_i = type_info.param_count;
                        while (param_i > 0) {
                            param_i -= 1;
                            stack.pop(StackInfo.EntryType.fromBool(
                                type_info.param_types.isSet(param_i),
                            ));
                        }
                        var result_i: u32 = 0;
                        while (result_i < type_info.result_count) : (result_i += 1)
                            stack.push(StackInfo.EntryType.fromBool(
                                type_info.result_types.isSet(result_i),
                            ));
                    }
                },
                .call_indirect => {
                    const type_idx = try leb.readULEB128(u32, reader);
                    assert(try leb.readULEB128(u32, reader) == 0);
                    if (unreachable_depth == 0) {
                        opcodes[pc.opcode] = @intFromEnum(Opcode.call_indirect);
                        pc.opcode += 1;

                        const type_info = &vm.types[type_idx];
                        var param_i = type_info.param_count;
                        while (param_i > 0) {
                            param_i -= 1;
                            stack.pop(StackInfo.EntryType.fromBool(
                                type_info.param_types.isSet(param_i),
                            ));
                        }
                        var result_i: u32 = 0;
                        while (result_i < type_info.result_count) : (result_i += 1)
                            stack.push(StackInfo.EntryType.fromBool(
                                type_info.result_types.isSet(result_i),
                            ));
                    }
                },
                .select,
                .drop,
                => |opc| if (unreachable_depth == 0) {
                    if (opc == .select) stack.pop(.i32);
                    const operand_type = stack.top();
                    stack.pop(operand_type);
                    if (opc == .select) {
                        stack.pop(operand_type);
                        stack.push(operand_type);
                    }
                    opcodes[pc.opcode] = @intFromEnum(switch (opc) {
                        .select => switch (operand_type) {
                            .i32 => Opcode.select_32,
                            .i64 => Opcode.select_64,
                        },
                        .drop => switch (operand_type) {
                            .i32 => Opcode.drop_32,
                            .i64 => Opcode.drop_64,
                        },
                        else => unreachable,
                    });
                    pc.opcode += 1;
                },
                .local_get,
                .local_set,
                .local_tee,
                => |opc| {
                    const local_idx = try leb.readULEB128(u32, reader);
                    if (unreachable_depth == 0) {
                        const local_type = stack.local(local_idx);
                        opcodes[pc.opcode] = @intFromEnum(switch (opc) {
                            .local_get => switch (local_type) {
                                .i32 => Opcode.local_get_32,
                                .i64 => Opcode.local_get_64,
                            },
                            .local_set => switch (local_type) {
                                .i32 => Opcode.local_set_32,
                                .i64 => Opcode.local_set_64,
                            },
                            .local_tee => switch (local_type) {
                                .i32 => Opcode.local_tee_32,
                                .i64 => Opcode.local_tee_64,
                            },
                            else => unreachable,
                        });
                        pc.opcode += 1;
                        operands[pc.operand] = stack.top_offset - stack.offsets[local_idx];
                        pc.operand += 1;
                        switch (opc) {
                            .local_get => stack.push(local_type),
                            .local_set => stack.pop(local_type),
                            .local_tee => {
                                stack.pop(local_type);
                                stack.push(local_type);
                            },
                            else => unreachable,
                        }
                    }
                },
                .global_get,
                .global_set,
                => |opc| {
                    const global_idx = try leb.readULEB128(u32, reader);
                    if (unreachable_depth == 0) {
                        const global_type = StackInfo.EntryType.i32; // all globals assumed to be i32
                        opcodes[pc.opcode] = @intFromEnum(switch (opc) {
                            .global_get => switch (global_idx) {
                                0 => Opcode.global_get_0_32,
                                else => Opcode.global_get_32,
                            },
                            .global_set => switch (global_idx) {
                                0 => Opcode.global_set_0_32,
                                else => Opcode.global_set_32,
                            },
                            else => unreachable,
                        });
                        pc.opcode += 1;
                        if (global_idx != 0) {
                            operands[pc.operand] = global_idx;
                            pc.operand += 1;
                        }
                        switch (opc) {
                            .global_get => stack.push(global_type),
                            .global_set => stack.pop(global_type),
                            else => unreachable,
                        }
                    }
                },
                .i32_load,
                .i64_load,
                .f32_load,
                .f64_load,
                .i32_load8_s,
                .i32_load8_u,
                .i32_load16_s,
                .i32_load16_u,
                .i64_load8_s,
                .i64_load8_u,
                .i64_load16_s,
                .i64_load16_u,
                .i64_load32_s,
                .i64_load32_u,
                .i32_store,
                .i64_store,
                .f32_store,
                .f64_store,
                .i32_store8,
                .i32_store16,
                .i64_store8,
                .i64_store16,
                .i64_store32,
                => |opc| {
                    const alignment = try leb.readULEB128(u32, reader);
                    const offset = try leb.readULEB128(u32, reader);
                    _ = alignment;
                    if (unreachable_depth == 0) {
                        switch (opc) {
                            else => {},
                            .i64_store8, .i64_store16, .i64_store32 => {
                                opcodes[pc.opcode] = @intFromEnum(Opcode.drop_32);
                                pc.opcode += 1;
                            },
                        }
                        opcodes[pc.opcode] = @intFromEnum(switch (opc) {
                            .i32_load8_s, .i32_load8_u, .i64_load8_s, .i64_load8_u => switch (offset) {
                                0 => Opcode.load_0_8,
                                else => Opcode.load_8,
                            },
                            .i32_load16_s, .i32_load16_u, .i64_load16_s, .i64_load16_u => switch (offset) {
                                0 => Opcode.load_0_16,
                                else => Opcode.load_16,
                            },
                            .i32_load, .f32_load, .i64_load32_s, .i64_load32_u => switch (offset) {
                                0 => Opcode.load_0_32,
                                else => Opcode.load_32,
                            },
                            .i64_load, .f64_load => switch (offset) {
                                0 => Opcode.load_0_64,
                                else => Opcode.load_64,
                            },
                            .i32_store8, .i64_store8 => switch (offset) {
                                0 => Opcode.store_0_8,
                                else => Opcode.store_8,
                            },
                            .i32_store16, .i64_store16 => switch (offset) {
                                0 => Opcode.store_0_16,
                                else => Opcode.store_16,
                            },
                            .i32_store, .f32_store, .i64_store32 => switch (offset) {
                                0 => Opcode.store_0_32,
                                else => Opcode.store_32,
                            },
                            .i64_store, .f64_store => switch (offset) {
                                0 => Opcode.store_0_64,
                                else => Opcode.store_64,
                            },
                            else => unreachable,
                        });
                        pc.opcode += 1;
                        switch (offset) {
                            0 => {},
                            else => {
                                operands[pc.operand] = offset;
                                pc.operand += 1;
                            },
                        }
                        switch (opc) {
                            else => {},
                            .i32_load8_s, .i64_load8_s => {
                                opcodes[pc.opcode] = @intFromEnum(Opcode.sext8_32);
                                pc.opcode += 1;
                            },
                            .i32_load16_s, .i64_load16_s => {
                                opcodes[pc.opcode] = @intFromEnum(Opcode.sext16_32);
                                pc.opcode += 1;
                            },
                        }
                        switch (opc) {
                            else => {},
                            .i64_load8_s, .i64_load16_s, .i64_load32_s => {
                                opcodes[pc.opcode] = @intFromEnum(Opcode.sext_64_32);
                                pc.opcode += 1;
                            },
                            .i64_load8_u, .i64_load16_u, .i64_load32_u => {
                                opcodes[pc.opcode] = @intFromEnum(Opcode.zext_64_32);
                                pc.opcode += 1;
                            },
                        }

                        offset_counts[@intFromBool(offset != 0)] += 1;
                        max_offset = @max(offset, max_offset);
                    }
                },
                .memory_size,
                .memory_grow,
                => |opc| {
                    assert(try reader.readByte() == 0);
                    if (unreachable_depth == 0) {
                        opcodes[pc.opcode] = @intFromEnum(switch (opc) {
                            .memory_size => Opcode.mem_size,
                            .memory_grow => Opcode.mem_grow,
                            else => unreachable,
                        });
                        pc.opcode += 1;
                    }
                },
                .i32_const,
                .f32_const,
                => |opc| {
                    const value = switch (opc) {
                        .i32_const => @as(u32, @bitCast(try leb.readILEB128(i32, reader))),
                        .f32_const => try reader.readVarInt(u32, .little, 4),
                        else => unreachable,
                    };
                    if (unreachable_depth == 0) {
                        switch (value) {
                            0 => opcodes[pc.opcode] = @intFromEnum(Opcode.const_0_32),
                            1 => opcodes[pc.opcode] = @intFromEnum(Opcode.const_1_32),
                            else => {
                                opcodes[pc.opcode] = @intFromEnum(Opcode.const_32);
                                operands[pc.operand] = value;
                                pc.operand += 1;
                            },
                            // math.maxInt(i32) => opcodes[pc.opcode] = @intFromEnum(Opcode.const_umax_32),
                        }
                        pc.opcode += 1;
                    }
                },
                .i64_const,
                .f64_const,
                => |opc| {
                    const value = switch (opc) {
                        .i64_const => @as(u64, @bitCast(try leb.readILEB128(i64, reader))),
                        .f64_const => try reader.readVarInt(u64, .little, 8),
                        else => unreachable,
                    };
                    if (unreachable_depth == 0) {
                        switch (value) {
                            0 => opcodes[pc.opcode] = @intFromEnum(Opcode.const_0_64),
                            1 => opcodes[pc.opcode] = @intFromEnum(Opcode.const_1_64),
                            else => {
                                opcodes[pc.opcode] = @intFromEnum(Opcode.const_64);
                                operands[pc.operand + 0] = @truncate(value >> 0);
                                operands[pc.operand + 1] = @truncate(value >> 32);
                                pc.operand += 2;
                            },
                            math.maxInt(u64) => opcodes[pc.opcode] = @intFromEnum(Opcode.const_umax_64),
                        }
                        pc.opcode += 1;
                    }
                },
                else => |opc| if (unreachable_depth == 0) {
                    opcodes[pc.opcode] = @intFromEnum(switch (opc) {
                        .i32_eqz => Opcode.eqz_32,
                        .i32_eq => Opcode.eq_32,
                        .i32_ne => Opcode.ne_32,
                        .i32_lt_s => Opcode.slt_32,
                        .i32_lt_u => Opcode.ult_32,
                        .i32_gt_s => Opcode.sgt_32,
                        .i32_gt_u => Opcode.ugt_32,
                        .i32_le_s => Opcode.sle_32,
                        .i32_le_u => Opcode.ule_32,
                        .i32_ge_s => Opcode.sge_32,
                        .i32_ge_u => Opcode.uge_32,
                        .i64_eqz => Opcode.eqz_64,
                        .i64_eq => Opcode.eq_64,
                        .i64_ne => Opcode.ne_64,
                        .i64_lt_s => Opcode.slt_64,
                        .i64_lt_u => Opcode.ult_64,
                        .i64_gt_s => Opcode.sgt_64,
                        .i64_gt_u => Opcode.ugt_64,
                        .i64_le_s => Opcode.sle_64,
                        .i64_le_u => Opcode.ule_64,
                        .i64_ge_s => Opcode.sge_64,
                        .i64_ge_u => Opcode.uge_64,
                        .f32_eq => Opcode.feq_32,
                        .f32_ne => Opcode.fne_32,
                        .f32_lt => Opcode.flt_32,
                        .f32_gt => Opcode.fgt_32,
                        .f32_le => Opcode.fle_32,
                        .f32_ge => Opcode.fge_32,
                        .f64_eq => Opcode.feq_64,
                        .f64_ne => Opcode.fne_64,
                        .f64_lt => Opcode.flt_64,
                        .f64_gt => Opcode.fgt_64,
                        .f64_le => Opcode.fle_64,
                        .f64_ge => Opcode.fge_64,
                        .i32_clz => Opcode.clz_32,
                        .i32_ctz => Opcode.ctz_32,
                        .i32_popcnt => Opcode.popcnt_32,
                        .i32_add => Opcode.add_32,
                        .i32_sub => Opcode.sub_32,
                        .i32_mul => Opcode.mul_32,
                        .i32_div_s => Opcode.sdiv_32,
                        .i32_div_u => Opcode.udiv_32,
                        .i32_rem_s => Opcode.srem_32,
                        .i32_rem_u => Opcode.urem_32,
                        .i32_and => Opcode.and_32,
                        .i32_or => Opcode.or_32,
                        .i32_xor => Opcode.xor_32,
                        .i32_shl => Opcode.shl_32,
                        .i32_shr_s => Opcode.ashr_32,
                        .i32_shr_u => Opcode.lshr_32,
                        .i32_rotl => Opcode.rol_32,
                        .i32_rotr => Opcode.ror_32,
                        .i64_clz => Opcode.clz_64,
                        .i64_ctz => Opcode.ctz_64,
                        .i64_popcnt => Opcode.popcnt_64,
                        .i64_add => Opcode.add_64,
                        .i64_sub => Opcode.sub_64,
                        .i64_mul => Opcode.mul_64,
                        .i64_div_s => Opcode.sdiv_64,
                        .i64_div_u => Opcode.udiv_64,
                        .i64_rem_s => Opcode.srem_64,
                        .i64_rem_u => Opcode.urem_64,
                        .i64_and => Opcode.and_64,
                        .i64_or => Opcode.or_64,
                        .i64_xor => Opcode.xor_64,
                        .i64_shl => Opcode.shl_64,
                        .i64_shr_s => Opcode.ashr_64,
                        .i64_shr_u => Opcode.lshr_64,
                        .i64_rotl => Opcode.rol_64,
                        .i64_rotr => Opcode.ror_64,
                        .f32_abs => Opcode.fabs_32,
                        .f32_neg => Opcode.fneg_32,
                        .f32_ceil => Opcode.ceil_32,
                        .f32_floor => Opcode.floor_32,
                        .f32_trunc => Opcode.trunc_32,
                        .f32_nearest => Opcode.nearest_32,
                        .f32_sqrt => Opcode.sqrt_32,
                        .f32_add => Opcode.fadd_32,
                        .f32_sub => Opcode.fsub_32,
                        .f32_mul => Opcode.fmul_32,
                        .f32_div => Opcode.fdiv_32,
                        .f32_min => Opcode.fmin_32,
                        .f32_max => Opcode.fmax_32,
                        .f32_copysign => Opcode.copysign_32,
                        .f64_abs => Opcode.fabs_64,
                        .f64_neg => Opcode.fneg_64,
                        .f64_ceil => Opcode.ceil_64,
                        .f64_floor => Opcode.floor_64,
                        .f64_trunc => Opcode.trunc_64,
                        .f64_nearest => Opcode.nearest_64,
                        .f64_sqrt => Opcode.sqrt_64,
                        .f64_add => Opcode.fadd_64,
                        .f64_sub => Opcode.fsub_64,
                        .f64_mul => Opcode.fmul_64,
                        .f64_div => Opcode.fdiv_64,
                        .f64_min => Opcode.fmin_64,
                        .f64_max => Opcode.fmax_64,
                        .f64_copysign => Opcode.copysign_64,
                        .i32_wrap_i64 => Opcode.wrap_32_64,
                        .i32_trunc_f32_s => Opcode.ftos_32_32,
                        .i32_trunc_f32_u => Opcode.ftou_32_32,
                        .i32_trunc_f64_s => Opcode.ftos_32_64,
                        .i32_trunc_f64_u => Opcode.ftou_32_64,
                        .i64_extend_i32_s => Opcode.sext_64_32,
                        .i64_extend_i32_u => Opcode.zext_64_32,
                        .i64_trunc_f32_s => Opcode.ftos_64_32,
                        .i64_trunc_f32_u => Opcode.ftou_64_32,
                        .i64_trunc_f64_s => Opcode.ftos_64_64,
                        .i64_trunc_f64_u => Opcode.ftou_64_64,
                        .f32_convert_i32_s => Opcode.stof_32_32,
                        .f32_convert_i32_u => Opcode.utof_32_32,
                        .f32_convert_i64_s => Opcode.stof_32_64,
                        .f32_convert_i64_u => Opcode.utof_32_64,
                        .f32_demote_f64 => Opcode.ftof_32_64,
                        .f64_convert_i32_s => Opcode.stof_64_32,
                        .f64_convert_i32_u => Opcode.utof_64_32,
                        .f64_convert_i64_s => Opcode.stof_64_64,
                        .f64_convert_i64_u => Opcode.utof_64_64,
                        .f64_promote_f32 => Opcode.ftof_64_32,
                        .i32_extend8_s => Opcode.sext8_32,
                        .i32_extend16_s => Opcode.sext16_32,
                        .i64_extend8_s => Opcode.sext8_64,
                        .i64_extend16_s => Opcode.sext16_64,
                        .i64_extend32_s => Opcode.sext32_64,
                        else => unreachable,
                    });
                    pc.opcode += 1;
                },
                .misc_prefix => switch (prefixed_enum) {
                    .memory_copy => {
                        assert(try reader.readByte() == 0 and try reader.readByte() == 0);
                        if (unreachable_depth == 0) {
                            opcodes[pc.opcode] = @intFromEnum(Opcode.memcpy);
                            pc.opcode += 1;
                        }
                    },
                    .memory_fill => {
                        assert(try reader.readByte() == 0);
                        if (unreachable_depth == 0) {
                            opcodes[pc.opcode] = @intFromEnum(Opcode.memset);
                            pc.opcode += 1;
                        }
                    },
                    else => unreachable,
                },
            }
            state = switch (opcode_enum) {
                else => .default,
                .i32_eqz => .bool_not,
            };

            for (opcodes[old_pc.opcode..pc.opcode], 0..) |o, i| {
                decode_log.debug("decoded opcode[{d}] = {d}", .{ old_pc.opcode + i, o });
            }
            for (operands[old_pc.operand..pc.operand], 0..) |o, i| {
                decode_log.debug("decoded operand[{d}] = {d}", .{ old_pc.operand + i, o });
            }
        }
    }

    fn br(vm: *VirtualMachine, comptime Result: type) void {
        const stack_adjust = vm.operands[vm.pc.operand];

        const result = vm.pop(Result);
        vm.stack_top -= stack_adjust;
        vm.push(Result, result);

        vm.pc.opcode = vm.operands[vm.pc.operand + 1];
        vm.pc.operand = vm.operands[vm.pc.operand + 2];
    }

    fn @"return"(vm: *VirtualMachine, comptime Result: type) void {
        const stack_adjust = vm.operands[vm.pc.operand + 0];
        const frame_size = vm.operands[vm.pc.operand + 1];

        const result = vm.pop(Result);

        vm.stack_top -= stack_adjust;
        vm.pc.operand = vm.pop(u32);
        vm.pc.opcode = vm.pop(u32);

        vm.stack_top -= frame_size;
        vm.push(Result, result);
    }

    fn call(vm: *VirtualMachine, func: *const Function) void {
        const type_info = &vm.types[func.type_idx];
        func_log.debug("enter fn_id: {d}, param_count: {d}, result_count: {d}, locals_size: {d}", .{
            func.id, type_info.param_count, type_info.result_count, func.locals_size,
        });

        // Push zeroed locals to stack
        @memset(vm.stack[vm.stack_top..][0..func.locals_size], 0);
        vm.stack_top += func.locals_size;

        vm.push(u32, vm.pc.opcode);
        vm.push(u32, vm.pc.operand);

        vm.pc = func.entry_pc;
    }

    fn callImport(vm: *VirtualMachine, import: *const Import) void {
        switch (import.mod) {
            .wasi_snapshot_preview1 => switch (import.name) {
                .fd_prestat_get => {
                    const buf = vm.pop(u32);
                    const fd = vm.pop(i32);
                    vm.push(u32, @intFromEnum(wasi_fd_prestat_get(vm, fd, buf)));
                },
                .fd_prestat_dir_name => {
                    const path_len = vm.pop(u32);
                    const path = vm.pop(u32);
                    const fd = vm.pop(i32);
                    vm.push(u32, @intFromEnum(wasi_fd_prestat_dir_name(vm, fd, path, path_len)));
                },
                .fd_close => {
                    const fd = vm.pop(i32);
                    vm.push(u32, @intFromEnum(wasi_fd_close(vm, fd)));
                },
                .fd_read => {
                    const nread = vm.pop(u32);
                    const iovs_len = vm.pop(u32);
                    const iovs = vm.pop(u32);
                    const fd = vm.pop(i32);
                    vm.push(u32, @intFromEnum(wasi_fd_read(vm, fd, iovs, iovs_len, nread)));
                },
                .fd_filestat_get => {
                    const buf = vm.pop(u32);
                    const fd = vm.pop(i32);
                    vm.push(u32, @intFromEnum(wasi_fd_filestat_get(vm, fd, buf)));
                },
                .fd_filestat_set_size => {
                    const size = vm.pop(u64);
                    const fd = vm.pop(i32);
                    vm.push(u32, @intFromEnum(wasi_fd_filestat_set_size(vm, fd, size)));
                },
                .fd_filestat_set_times => {
                    @panic("TODO implement fd_filestat_set_times");
                },
                .fd_fdstat_get => {
                    const buf = vm.pop(u32);
                    const fd = vm.pop(i32);
                    vm.push(u32, @intFromEnum(wasi_fd_fdstat_get(vm, fd, buf)));
                },
                .fd_readdir => {
                    @panic("TODO implement fd_readdir");
                },
                .fd_write => {
                    const nwritten = vm.pop(u32);
                    const iovs_len = vm.pop(u32);
                    const iovs = vm.pop(u32);
                    const fd = vm.pop(i32);
                    vm.push(u32, @intFromEnum(wasi_fd_write(vm, fd, iovs, iovs_len, nwritten)));
                },
                .fd_pwrite => {
                    const nwritten = vm.pop(u32);
                    const offset = vm.pop(u64);
                    const iovs_len = vm.pop(u32);
                    const iovs = vm.pop(u32);
                    const fd = vm.pop(i32);
                    vm.push(u32, @intFromEnum(wasi_fd_pwrite(vm, fd, iovs, iovs_len, offset, nwritten)));
                },
                .proc_exit => {
                    stats_log.debug("memory length = {}\n", .{vm.memory_len});
                    std.c.exit(@as(c_int, @intCast(vm.pop(wasi.exitcode_t))));
                    unreachable;
                },
                .args_sizes_get => {
                    const argv_buf_size = vm.pop(u32);
                    const argc = vm.pop(u32);
                    vm.push(u32, @intFromEnum(wasi_args_sizes_get(vm, argc, argv_buf_size)));
                },
                .args_get => {
                    const argv_buf = vm.pop(u32);
                    const argv = vm.pop(u32);
                    vm.push(u32, @intFromEnum(wasi_args_get(vm, argv, argv_buf)));
                },
                .random_get => {
                    const buf_len = vm.pop(u32);
                    const buf = vm.pop(u32);
                    vm.push(u32, @intFromEnum(wasi_random_get(vm, buf, buf_len)));
                },
                .environ_sizes_get => {
                    @panic("TODO implement environ_sizes_get");
                },
                .environ_get => {
                    @panic("TODO implement environ_get");
                },
                .path_filestat_get => {
                    const buf = vm.pop(u32);
                    const path_len = vm.pop(u32);
                    const path = vm.pop(u32);
                    const flags: wasi.lookupflags_t = @bitCast(vm.pop(u32));
                    const fd = vm.pop(i32);
                    const result: u16 = @intFromEnum(wasi_path_filestat_get(vm, fd, flags, path, path_len, buf));
                    vm.push(u32, @intCast(result));
                },
                .path_create_directory => {
                    const path_len = vm.pop(u32);
                    const path = vm.pop(u32);
                    const fd = vm.pop(i32);
                    vm.push(u32, @intFromEnum(wasi_path_create_directory(vm, fd, path, path_len)));
                },
                .path_rename => {
                    const new_path_len = vm.pop(u32);
                    const new_path = vm.pop(u32);
                    const new_fd = vm.pop(i32);
                    const old_path_len = vm.pop(u32);
                    const old_path = vm.pop(u32);
                    const old_fd = vm.pop(i32);
                    vm.push(u32, @intFromEnum(wasi_path_rename(
                        vm,
                        old_fd,
                        old_path,
                        old_path_len,
                        new_fd,
                        new_path,
                        new_path_len,
                    )));
                },
                .path_open => {
                    const fd = vm.pop(u32);
                    const fs_flags: wasi.fdflags_t = @bitCast(@as(u16, @truncate(vm.pop(u32))));
                    const fs_rights_inheriting: wasi.rights_t = @bitCast(vm.pop(u64));
                    const fs_rights_base: wasi.rights_t = @bitCast(vm.pop(u64));
                    const oflags: wasi.oflags_t = @bitCast(@as(u16, @truncate(vm.pop(u32))));
                    const path_len = vm.pop(u32);
                    const path = vm.pop(u32);
                    const dirflags: wasi.lookupflags_t = @bitCast(vm.pop(u32));
                    const dirfd = vm.pop(i32);
                    vm.push(u32, @intFromEnum(wasi_path_open(
                        vm,
                        dirfd,
                        dirflags,
                        path,
                        path_len,
                        oflags,
                        fs_rights_base,
                        fs_rights_inheriting,
                        fs_flags,
                        fd,
                    )));
                },
                .path_remove_directory => {
                    @panic("TODO implement path_remove_directory");
                },
                .path_unlink_file => {
                    @panic("TODO implement path_unlink_file");
                },
                .clock_time_get => {
                    const timestamp = vm.pop(u32);
                    const precision = vm.pop(u64);
                    const clock_id: wasi.clockid_t = @enumFromInt(vm.pop(u32));
                    vm.push(u32, @intFromEnum(wasi_clock_time_get(vm, clock_id, precision, timestamp)));
                },
                .fd_pread => {
                    @panic("TODO implement fd_pread");
                },
                .debug => {
                    const number = vm.pop(u64);
                    const text = vm.pop(u32);
                    wasi_debug(vm, text, number);
                },
                .debug_slice => {
                    const len = vm.pop(u32);
                    const ptr = vm.pop(u32);
                    wasi_debug_slice(vm, ptr, len);
                },
            },
        }
    }

    fn push(vm: *VirtualMachine, comptime T: type, value: T) void {
        if (@sizeOf(T) == 0) return;
        switch (@bitSizeOf(T)) {
            32 => {
                vm.stack[vm.stack_top + 0] = @bitCast(value);
                vm.stack_top += 1;
            },
            64 => {
                vm.stack[vm.stack_top + 0] = @truncate(@as(u64, @bitCast(value)));
                vm.stack[vm.stack_top + 1] = @truncate(@as(u64, @bitCast(value)) >> 32);
                vm.stack_top += 2;
            },
            else => @compileError("bad push type"),
        }
    }

    fn pop(vm: *VirtualMachine, comptime T: type) T {
        if (@sizeOf(T) == 0) return undefined;
        switch (@bitSizeOf(T)) {
            32 => {
                vm.stack_top -= 1;
                return @bitCast(vm.stack[vm.stack_top + 0]);
            },
            64 => {
                vm.stack_top -= 2;
                return @bitCast(vm.stack[vm.stack_top + 0] | @as(u64, vm.stack[vm.stack_top + 1]) << 32);
            },
            else => @compileError("bad pop type"),
        }
    }

    fn run(vm: *VirtualMachine) noreturn {
        const opcodes = vm.opcodes;
        const operands = vm.operands;
        const pc = &vm.pc;
        var global_0: u32 = vm.globals[0];
        defer vm.globals[0] = global_0;
        while (true) {
            const op: Opcode = @enumFromInt(opcodes[pc.opcode]);
            cpu_log.debug("stack[{d}:{d}]={x}:{x} pc={x}:{x} op={d}", .{
                vm.stack_top - 2,
                vm.stack_top - 1,
                vm.stack[vm.stack_top - 2],
                vm.stack[vm.stack_top - 1],
                pc.opcode,
                pc.operand,
                @intFromEnum(op),
            });
            cpu_log.debug("op={s}", .{@tagName(op)});
            pc.opcode += 1;
            switch (op) {
                .@"unreachable" => @panic("unreachable reached"),
                .br_void => {
                    vm.br(void);
                },
                .br_32 => {
                    vm.br(u32);
                },
                .br_64 => {
                    vm.br(u64);
                },
                .br_nez_void => {
                    if (vm.pop(u32) != 0) {
                        vm.br(void);
                    } else {
                        pc.operand += 3;
                    }
                },
                .br_nez_32 => {
                    if (vm.pop(u32) != 0) {
                        vm.br(u32);
                    } else {
                        pc.operand += 3;
                    }
                },
                .br_nez_64 => {
                    if (vm.pop(u32) != 0) {
                        vm.br(u64);
                    } else {
                        pc.operand += 3;
                    }
                },
                .br_eqz_void => {
                    if (vm.pop(u32) == 0) {
                        vm.br(void);
                    } else {
                        pc.operand += 3;
                    }
                },
                .br_eqz_32 => {
                    if (vm.pop(u32) == 0) {
                        vm.br(u32);
                    } else {
                        pc.operand += 3;
                    }
                },
                .br_eqz_64 => {
                    if (vm.pop(u32) == 0) {
                        vm.br(u64);
                    } else {
                        pc.operand += 3;
                    }
                },
                .br_table_void => {
                    const index = @min(vm.pop(u32), operands[pc.operand]);
                    pc.operand += 1 + index * 3;
                    vm.br(void);
                },
                .br_table_32 => {
                    const index = @min(vm.pop(u32), operands[pc.operand]);
                    pc.operand += 1 + index * 3;
                    vm.br(u32);
                },
                .br_table_64 => {
                    const index = @min(vm.pop(u32), operands[pc.operand]);
                    pc.operand += 1 + index * 3;
                    vm.br(u64);
                },
                .return_void => {
                    vm.@"return"(void);
                },
                .return_32 => {
                    vm.@"return"(u32);
                },
                .return_64 => {
                    vm.@"return"(u64);
                },
                .call_import => {
                    const import_idx = opcodes[pc.opcode];
                    pc.opcode += 1;
                    vm.callImport(&vm.imports[import_idx]);
                },
                .call_func => {
                    const func_idx = operands[pc.operand];
                    pc.operand += 1;
                    vm.call(&vm.functions[func_idx]);
                },
                .call_indirect => {
                    const fn_id = vm.table[vm.pop(u32)];
                    if (fn_id < vm.imports.len)
                        vm.callImport(&vm.imports[fn_id])
                    else
                        vm.call(&vm.functions[fn_id - @as(u32, @truncate(vm.imports.len))]);
                },
                .drop_32 => {
                    vm.stack_top -= 1;
                },
                .drop_64 => {
                    vm.stack_top -= 2;
                },
                .select_32 => {
                    const c = vm.pop(u32);
                    const b = vm.pop(u32);
                    const a = vm.pop(u32);
                    const result = if (c != 0) a else b;
                    vm.push(u32, result);
                },
                .select_64 => {
                    const c = vm.pop(u32);
                    const b = vm.pop(u64);
                    const a = vm.pop(u64);
                    const result = if (c != 0) a else b;
                    vm.push(u64, result);
                },
                .local_get_32 => {
                    const local = &vm.stack[vm.stack_top - operands[pc.operand]];
                    pc.operand += 1;
                    vm.push(u32, @as(u32, local.*));
                },
                .local_get_64 => {
                    const local = vm.stack[vm.stack_top - operands[pc.operand] ..][0..2];
                    pc.operand += 1;
                    vm.push(u64, local[0] | @as(u64, local[1]) << 32);
                },
                .local_set_32 => {
                    const local = &vm.stack[vm.stack_top - operands[pc.operand]];
                    pc.operand += 1;
                    local.* = vm.pop(u32);
                },
                .local_set_64 => {
                    const local = vm.stack[vm.stack_top - operands[pc.operand] ..][0..2];
                    pc.operand += 1;
                    const value = vm.pop(u64);
                    local[0] = @truncate(value >> 0);
                    local[1] = @truncate(value >> 32);
                },
                .local_tee_32 => {
                    const local = &vm.stack[vm.stack_top - operands[pc.operand]];
                    pc.operand += 1;
                    local.* = vm.stack[vm.stack_top - 1];
                },
                .local_tee_64 => {
                    const local = vm.stack[vm.stack_top - operands[pc.operand] ..][0..2];
                    pc.operand += 1;
                    local[0] = vm.stack[vm.stack_top - 2];
                    local[1] = vm.stack[vm.stack_top - 1];
                },
                .global_get_0_32 => {
                    vm.push(u32, global_0);
                },
                .global_get_32 => {
                    const idx = operands[pc.operand];
                    pc.operand += 1;
                    vm.push(u32, vm.globals[idx]);
                },
                .global_set_0_32 => {
                    global_0 = vm.pop(u32);
                },
                .global_set_32 => {
                    const idx = operands[pc.operand];
                    pc.operand += 1;
                    vm.globals[idx] = vm.pop(u32);
                },
                .load_0_8 => {
                    const address = vm.pop(u32);
                    vm.push(u32, vm.memory[address]);
                },
                .load_8 => {
                    const address = vm.pop(u32) + operands[pc.operand];
                    pc.operand += 1;
                    vm.push(u32, vm.memory[address]);
                },
                .load_0_16 => {
                    const address = vm.pop(u32);
                    vm.push(u32, mem.readVarInt(u16, vm.memory[address..][0..2], .little));
                },
                .load_16 => {
                    const address = vm.pop(u32) + operands[pc.operand];
                    pc.operand += 1;
                    vm.push(u32, mem.readVarInt(u16, vm.memory[address..][0..2], .little));
                },
                .load_0_32 => {
                    const address = vm.pop(u32);
                    vm.push(u32, mem.readVarInt(u32, vm.memory[address..][0..4], .little));
                },
                .load_32 => {
                    const address = vm.pop(u32) + operands[pc.operand];
                    pc.operand += 1;
                    vm.push(u32, mem.readVarInt(u32, vm.memory[address..][0..4], .little));
                },
                .load_0_64 => {
                    const address = vm.pop(u32);
                    vm.push(u64, mem.readVarInt(u64, vm.memory[address..][0..8], .little));
                },
                .load_64 => {
                    const address = vm.pop(u32) + operands[pc.operand];
                    pc.operand += 1;
                    vm.push(u64, mem.readVarInt(u64, vm.memory[address..][0..8], .little));
                },
                .store_0_8 => {
                    const value: u8 = @truncate(vm.pop(u32));
                    const address = vm.pop(u32);
                    vm.memory[address] = value;
                },
                .store_8 => {
                    const value: u8 = @truncate(vm.pop(u32));
                    const address = vm.pop(u32) + operands[pc.operand];
                    pc.operand += 1;
                    vm.memory[address] = value;
                },
                .store_0_16 => {
                    const value: u16 = @truncate(vm.pop(u32));
                    const address = vm.pop(u32);
                    mem.writeVarPackedInt(vm.memory[address..][0..2], 0, 16, value, .little);
                },
                .store_16 => {
                    const value: u16 = @truncate(vm.pop(u32));
                    const address = vm.pop(u32) + operands[pc.operand];
                    pc.operand += 1;
                    mem.writeVarPackedInt(vm.memory[address..][0..2], 0, 16, value, .little);
                },
                .store_0_32 => {
                    const value = vm.pop(u32);
                    const address = vm.pop(u32);
                    mem.writeVarPackedInt(vm.memory[address..][0..4], 0, 32, value, .little);
                },
                .store_32 => {
                    const value = vm.pop(u32);
                    const address = vm.pop(u32) + operands[pc.operand];
                    pc.operand += 1;
                    mem.writeVarPackedInt(vm.memory[address..][0..4], 0, 32, value, .little);
                },
                .store_0_64 => {
                    const value = vm.pop(u64);
                    const address = vm.pop(u32);
                    mem.writeVarPackedInt(vm.memory[address..][0..8], 0, 64, value, .little);
                },
                .store_64 => {
                    const value = vm.pop(u64);
                    const address = vm.pop(u32) + operands[pc.operand];
                    pc.operand += 1;
                    mem.writeVarPackedInt(vm.memory[address..][0..8], 0, 64, value, .little);
                },
                .mem_size => {
                    const page_count = @as(u32, vm.memory_len / wasm.page_size);
                    vm.push(u32, page_count);
                },
                .mem_grow => {
                    const page_count = vm.pop(u32);
                    const old_page_count = @as(u32, vm.memory_len / wasm.page_size);
                    const new_len = vm.memory_len + page_count * wasm.page_size;
                    if (new_len > vm.memory.len) {
                        vm.push(i32, -1);
                    } else {
                        vm.memory_len = new_len;
                        vm.push(u32, old_page_count);
                    }
                },
                .const_0_32 => {
                    vm.push(i32, @as(i32, 0));
                },
                .const_0_64 => {
                    vm.push(i64, @as(i64, 0));
                },
                .const_1_32 => {
                    vm.push(i32, @as(i32, 1));
                },
                .const_1_64 => {
                    vm.push(i64, @as(i64, 1));
                },
                .const_32 => {
                    const x = operands[pc.operand];
                    pc.operand += 1;
                    vm.push(i32, @intCast(x));
                },
                .const_64 => {
                    const x = operands[pc.operand] | @as(u64, operands[pc.operand + 1]) << 32;
                    pc.operand += 2;
                    vm.push(i64, @intCast(x));
                },
                .const_umax_32 => {
                    vm.push(i32, -1);
                },
                .const_umax_64 => {
                    vm.push(i64, -1);
                },
                .eqz_32 => {
                    const lhs = vm.pop(u32);
                    vm.push(u32, @intFromBool(lhs == 0));
                },
                .eq_32 => {
                    const rhs = vm.pop(u32);
                    const lhs = vm.pop(u32);
                    vm.push(u32, @intFromBool(lhs == rhs));
                },
                .ne_32 => {
                    const rhs = vm.pop(u32);
                    const lhs = vm.pop(u32);
                    vm.push(u32, @intFromBool(lhs != rhs));
                },
                .slt_32 => {
                    const rhs = vm.pop(i32);
                    const lhs = vm.pop(i32);
                    vm.push(u32, @intFromBool(lhs < rhs));
                },
                .ult_32 => {
                    const rhs = vm.pop(u32);
                    const lhs = vm.pop(u32);
                    vm.push(u32, @intFromBool(lhs < rhs));
                },
                .sgt_32 => {
                    const rhs = vm.pop(i32);
                    const lhs = vm.pop(i32);
                    vm.push(u32, @intFromBool(lhs > rhs));
                },
                .ugt_32 => {
                    const rhs = vm.pop(u32);
                    const lhs = vm.pop(u32);
                    vm.push(u32, @intFromBool(lhs > rhs));
                },
                .sle_32 => {
                    const rhs = vm.pop(i32);
                    const lhs = vm.pop(i32);
                    vm.push(u32, @intFromBool(lhs <= rhs));
                },
                .ule_32 => {
                    const rhs = vm.pop(u32);
                    const lhs = vm.pop(u32);
                    vm.push(u32, @intFromBool(lhs <= rhs));
                },
                .sge_32 => {
                    const rhs = vm.pop(i32);
                    const lhs = vm.pop(i32);
                    vm.push(u32, @intFromBool(lhs >= rhs));
                },
                .uge_32 => {
                    const rhs = vm.pop(u32);
                    const lhs = vm.pop(u32);
                    vm.push(u32, @intFromBool(lhs >= rhs));
                },
                .eqz_64 => {
                    const lhs = vm.pop(u64);
                    vm.push(u32, @intFromBool(lhs == 0));
                },
                .eq_64 => {
                    const rhs = vm.pop(u64);
                    const lhs = vm.pop(u64);
                    vm.push(u32, @intFromBool(lhs == rhs));
                },
                .ne_64 => {
                    const rhs = vm.pop(u64);
                    const lhs = vm.pop(u64);
                    vm.push(u32, @intFromBool(lhs != rhs));
                },
                .slt_64 => {
                    const rhs = vm.pop(i64);
                    const lhs = vm.pop(i64);
                    vm.push(u32, @intFromBool(lhs < rhs));
                },
                .ult_64 => {
                    const rhs = vm.pop(u64);
                    const lhs = vm.pop(u64);
                    vm.push(u32, @intFromBool(lhs < rhs));
                },
                .sgt_64 => {
                    const rhs = vm.pop(i64);
                    const lhs = vm.pop(i64);
                    vm.push(u32, @intFromBool(lhs > rhs));
                },
                .ugt_64 => {
                    const rhs = vm.pop(u64);
                    const lhs = vm.pop(u64);
                    vm.push(u32, @intFromBool(lhs > rhs));
                },
                .sle_64 => {
                    const rhs = vm.pop(i64);
                    const lhs = vm.pop(i64);
                    vm.push(u32, @intFromBool(lhs <= rhs));
                },
                .ule_64 => {
                    const rhs = vm.pop(u64);
                    const lhs = vm.pop(u64);
                    vm.push(u32, @intFromBool(lhs <= rhs));
                },
                .sge_64 => {
                    const rhs = vm.pop(i64);
                    const lhs = vm.pop(i64);
                    vm.push(u32, @intFromBool(lhs >= rhs));
                },
                .uge_64 => {
                    const rhs = vm.pop(u64);
                    const lhs = vm.pop(u64);
                    vm.push(u32, @intFromBool(lhs >= rhs));
                },
                .feq_32 => {
                    const rhs = vm.pop(f32);
                    const lhs = vm.pop(f32);
                    vm.push(u32, @intFromBool(lhs == rhs));
                },
                .fne_32 => {
                    const rhs = vm.pop(f32);
                    const lhs = vm.pop(f32);
                    vm.push(u32, @intFromBool(lhs != rhs));
                },
                .flt_32 => {
                    const rhs = vm.pop(f32);
                    const lhs = vm.pop(f32);
                    vm.push(u32, @intFromBool(lhs < rhs));
                },
                .fgt_32 => {
                    const rhs = vm.pop(f32);
                    const lhs = vm.pop(f32);
                    vm.push(u32, @intFromBool(lhs > rhs));
                },
                .fle_32 => {
                    const rhs = vm.pop(f32);
                    const lhs = vm.pop(f32);
                    vm.push(u32, @intFromBool(lhs <= rhs));
                },
                .fge_32 => {
                    const rhs = vm.pop(f32);
                    const lhs = vm.pop(f32);
                    vm.push(u32, @intFromBool(lhs >= rhs));
                },
                .feq_64 => {
                    const rhs = vm.pop(f64);
                    const lhs = vm.pop(f64);
                    vm.push(u32, @intFromBool(lhs == rhs));
                },
                .fne_64 => {
                    const rhs = vm.pop(f64);
                    const lhs = vm.pop(f64);
                    vm.push(u32, @intFromBool(lhs != rhs));
                },
                .flt_64 => {
                    const rhs = vm.pop(f64);
                    const lhs = vm.pop(f64);
                    vm.push(u32, @intFromBool(lhs <= rhs));
                },
                .fgt_64 => {
                    const rhs = vm.pop(f64);
                    const lhs = vm.pop(f64);
                    vm.push(u32, @intFromBool(lhs > rhs));
                },
                .fle_64 => {
                    const rhs = vm.pop(f64);
                    const lhs = vm.pop(f64);
                    vm.push(u32, @intFromBool(lhs <= rhs));
                },
                .fge_64 => {
                    const rhs = vm.pop(f64);
                    const lhs = vm.pop(f64);
                    vm.push(u32, @intFromBool(lhs >= rhs));
                },
                .clz_32 => {
                    vm.push(u32, @clz(vm.pop(u32)));
                },
                .ctz_32 => {
                    vm.push(u32, @ctz(vm.pop(u32)));
                },
                .popcnt_32 => {
                    vm.push(u32, @popCount(vm.pop(u32)));
                },
                .add_32 => {
                    const rhs = vm.pop(u32);
                    const lhs = vm.pop(u32);
                    vm.push(u32, lhs +% rhs);
                },
                .sub_32 => {
                    const rhs = vm.pop(u32);
                    const lhs = vm.pop(u32);
                    vm.push(u32, lhs -% rhs);
                },
                .mul_32 => {
                    const rhs = vm.pop(u32);
                    const lhs = vm.pop(u32);
                    vm.push(u32, lhs *% rhs);
                },
                .sdiv_32 => {
                    const rhs = vm.pop(i32);
                    const lhs = vm.pop(i32);
                    vm.push(i32, @divTrunc(lhs, rhs));
                },
                .udiv_32 => {
                    const rhs = vm.pop(u32);
                    const lhs = vm.pop(u32);
                    vm.push(u32, @divTrunc(lhs, rhs));
                },
                .srem_32 => {
                    const rhs = vm.pop(i32);
                    const lhs = vm.pop(i32);
                    vm.push(i32, @rem(lhs, rhs));
                },
                .urem_32 => {
                    const rhs = vm.pop(u32);
                    const lhs = vm.pop(u32);
                    vm.push(u32, @rem(lhs, rhs));
                },
                .and_32 => {
                    const rhs = vm.pop(u32);
                    const lhs = vm.pop(u32);
                    vm.push(u32, lhs & rhs);
                },
                .or_32 => {
                    const rhs = vm.pop(u32);
                    const lhs = vm.pop(u32);
                    vm.push(u32, lhs | rhs);
                },
                .xor_32 => {
                    const rhs = vm.pop(u32);
                    const lhs = vm.pop(u32);
                    vm.push(u32, lhs ^ rhs);
                },
                .shl_32 => {
                    const rhs = vm.pop(u32);
                    const lhs = vm.pop(u32);
                    vm.push(u32, lhs << @truncate(rhs));
                },
                .ashr_32 => {
                    const rhs = vm.pop(u32);
                    const lhs = vm.pop(i32);
                    vm.push(i32, lhs >> @truncate(rhs));
                },
                .lshr_32 => {
                    const rhs = vm.pop(u32);
                    const lhs = vm.pop(u32);
                    vm.push(u32, lhs >> @truncate(rhs));
                },
                .rol_32 => {
                    const rhs = vm.pop(u32);
                    const lhs = vm.pop(u32);
                    vm.push(u32, math.rotl(u32, lhs, rhs % 32));
                },
                .ror_32 => {
                    const rhs = vm.pop(u32);
                    const lhs = vm.pop(u32);
                    vm.push(u32, math.rotr(u32, lhs, rhs % 32));
                },
                .clz_64 => {
                    vm.push(u64, @clz(vm.pop(u64)));
                },
                .ctz_64 => {
                    vm.push(u64, @ctz(vm.pop(u64)));
                },
                .popcnt_64 => {
                    vm.push(u64, @popCount(vm.pop(u64)));
                },
                .add_64 => {
                    const rhs = vm.pop(u64);
                    const lhs = vm.pop(u64);
                    vm.push(u64, lhs +% rhs);
                },
                .sub_64 => {
                    const rhs = vm.pop(u64);
                    const lhs = vm.pop(u64);
                    vm.push(u64, lhs -% rhs);
                },
                .mul_64 => {
                    const rhs = vm.pop(u64);
                    const lhs = vm.pop(u64);
                    vm.push(u64, lhs *% rhs);
                },
                .sdiv_64 => {
                    const rhs = vm.pop(i64);
                    const lhs = vm.pop(i64);
                    vm.push(i64, @divTrunc(lhs, rhs));
                },
                .udiv_64 => {
                    const rhs = vm.pop(u64);
                    const lhs = vm.pop(u64);
                    vm.push(u64, @divTrunc(lhs, rhs));
                },
                .srem_64 => {
                    const rhs = vm.pop(i64);
                    const lhs = vm.pop(i64);
                    vm.push(i64, @rem(lhs, rhs));
                },
                .urem_64 => {
                    const rhs = vm.pop(u64);
                    const lhs = vm.pop(u64);
                    vm.push(u64, @rem(lhs, rhs));
                },
                .and_64 => {
                    const rhs = vm.pop(u64);
                    const lhs = vm.pop(u64);
                    vm.push(u64, lhs & rhs);
                },
                .or_64 => {
                    const rhs = vm.pop(u64);
                    const lhs = vm.pop(u64);
                    vm.push(u64, lhs | rhs);
                },
                .xor_64 => {
                    const rhs = vm.pop(u64);
                    const lhs = vm.pop(u64);
                    vm.push(u64, lhs ^ rhs);
                },
                .shl_64 => {
                    const rhs = vm.pop(u64);
                    const lhs = vm.pop(u64);
                    vm.push(u64, lhs << @truncate(rhs));
                },
                .ashr_64 => {
                    const rhs = vm.pop(u64);
                    const lhs = vm.pop(i64);
                    vm.push(i64, lhs >> @truncate(rhs));
                },
                .lshr_64 => {
                    const rhs = vm.pop(u64);
                    const lhs = vm.pop(u64);
                    vm.push(u64, lhs >> @truncate(rhs));
                },
                .rol_64 => {
                    const rhs = vm.pop(u64);
                    const lhs = vm.pop(u64);
                    vm.push(u64, math.rotl(u64, lhs, rhs % 64));
                },
                .ror_64 => {
                    const rhs = vm.pop(u64);
                    const lhs = vm.pop(u64);
                    vm.push(u64, math.rotr(u64, lhs, rhs % 64));
                },
                .fabs_32 => {
                    vm.push(f32, @abs(vm.pop(f32)));
                },
                .fneg_32 => {
                    vm.push(f32, -vm.pop(f32));
                },
                .ceil_32 => {
                    vm.push(f32, @ceil(vm.pop(f32)));
                },
                .floor_32 => {
                    vm.push(f32, @floor(vm.pop(f32)));
                },
                .trunc_32 => {
                    vm.push(f32, @trunc(vm.pop(f32)));
                },
                .nearest_32 => {
                    vm.push(f32, @round(vm.pop(f32)));
                },
                .sqrt_32 => {
                    vm.push(f32, @sqrt(vm.pop(f32)));
                },
                .fadd_32 => {
                    const rhs = vm.pop(f32);
                    const lhs = vm.pop(f32);
                    vm.push(f32, lhs + rhs);
                },
                .fsub_32 => {
                    const rhs = vm.pop(f32);
                    const lhs = vm.pop(f32);
                    vm.push(f32, lhs - rhs);
                },
                .fmul_32 => {
                    const rhs = vm.pop(f32);
                    const lhs = vm.pop(f32);
                    vm.push(f32, lhs * rhs);
                },
                .fdiv_32 => {
                    const rhs = vm.pop(f32);
                    const lhs = vm.pop(f32);
                    vm.push(f32, lhs / rhs);
                },
                .fmin_32 => {
                    const rhs = vm.pop(f32);
                    const lhs = vm.pop(f32);
                    vm.push(f32, @min(lhs, rhs));
                },
                .fmax_32 => {
                    const rhs = vm.pop(f32);
                    const lhs = vm.pop(f32);
                    vm.push(f32, @max(lhs, rhs));
                },
                .copysign_32 => {
                    const rhs = vm.pop(f32);
                    const lhs = vm.pop(f32);
                    vm.push(f32, math.copysign(lhs, rhs));
                },
                .fabs_64 => {
                    vm.push(f64, @abs(vm.pop(f64)));
                },
                .fneg_64 => {
                    vm.push(f64, -vm.pop(f64));
                },
                .ceil_64 => {
                    vm.push(f64, @ceil(vm.pop(f64)));
                },
                .floor_64 => {
                    vm.push(f64, @floor(vm.pop(f64)));
                },
                .trunc_64 => {
                    vm.push(f64, @trunc(vm.pop(f64)));
                },
                .nearest_64 => {
                    vm.push(f64, @round(vm.pop(f64)));
                },
                .sqrt_64 => {
                    vm.push(f64, @sqrt(vm.pop(f64)));
                },
                .fadd_64 => {
                    const rhs = vm.pop(f64);
                    const lhs = vm.pop(f64);
                    vm.push(f64, lhs + rhs);
                },
                .fsub_64 => {
                    const rhs = vm.pop(f64);
                    const lhs = vm.pop(f64);
                    vm.push(f64, lhs - rhs);
                },
                .fmul_64 => {
                    const rhs = vm.pop(f64);
                    const lhs = vm.pop(f64);
                    vm.push(f64, lhs * rhs);
                },
                .fdiv_64 => {
                    const rhs = vm.pop(f64);
                    const lhs = vm.pop(f64);
                    vm.push(f64, lhs / rhs);
                },
                .fmin_64 => {
                    const rhs = vm.pop(f64);
                    const lhs = vm.pop(f64);
                    vm.push(f64, @min(lhs, rhs));
                },
                .fmax_64 => {
                    const rhs = vm.pop(f64);
                    const lhs = vm.pop(f64);
                    vm.push(f64, @max(lhs, rhs));
                },
                .copysign_64 => {
                    const rhs = vm.pop(f64);
                    const lhs = vm.pop(f64);
                    vm.push(f64, math.copysign(lhs, rhs));
                },
                .ftos_32_32 => {
                    vm.push(i32, @intFromFloat(vm.pop(f32)));
                },
                .ftou_32_32 => {
                    vm.push(u32, @intFromFloat(vm.pop(f32)));
                },
                .ftos_32_64 => {
                    vm.push(i32, @intFromFloat(vm.pop(f64)));
                },
                .ftou_32_64 => {
                    vm.push(u32, @intFromFloat(vm.pop(f64)));
                },
                .sext_64_32 => {
                    vm.push(i32, @as(i32, @bitCast(vm.stack[vm.stack_top - 1])) >> 31);
                },
                .ftos_64_32 => {
                    vm.push(i64, @intFromFloat(vm.pop(f32)));
                },
                .ftou_64_32 => {
                    vm.push(u64, @intFromFloat(vm.pop(f32)));
                },
                .ftos_64_64 => {
                    vm.push(i64, @intFromFloat(vm.pop(f64)));
                },
                .ftou_64_64 => {
                    vm.push(u64, @intFromFloat(vm.pop(f64)));
                },
                .stof_32_32 => {
                    vm.push(f32, @floatFromInt(vm.pop(i32)));
                },
                .utof_32_32 => {
                    vm.push(f32, @floatFromInt(vm.pop(u32)));
                },
                .stof_32_64 => {
                    vm.push(f32, @floatFromInt(vm.pop(i64)));
                },
                .utof_32_64 => {
                    vm.push(f32, @floatFromInt(vm.pop(u64)));
                },
                .ftof_32_64 => {
                    vm.push(f32, @floatCast(vm.pop(f64)));
                },
                .stof_64_32 => {
                    vm.push(f64, @floatFromInt(vm.pop(i32)));
                },
                .utof_64_32 => {
                    vm.push(f64, @floatFromInt(vm.pop(u32)));
                },
                .stof_64_64 => {
                    vm.push(f64, @floatFromInt(vm.pop(i64)));
                },
                .utof_64_64 => {
                    vm.push(f64, @floatFromInt(vm.pop(u64)));
                },
                .ftof_64_32 => {
                    vm.push(f64, @as(f64, vm.pop(f32)));
                },
                .sext8_32 => {
                    vm.push(i32, @truncate(vm.pop(i32)));
                },
                .sext16_32 => {
                    vm.push(i32, @truncate(vm.pop(i32)));
                },
                .sext8_64 => {
                    vm.push(i64, @truncate(vm.pop(i64)));
                },
                .sext16_64 => {
                    vm.push(i64, @truncate(vm.pop(i64)));
                },
                .sext32_64 => {
                    vm.push(i64, @truncate(vm.pop(i64)));
                },
                .memcpy => {
                    const n = vm.pop(u32);
                    const src = vm.pop(u32);
                    const dest = vm.pop(u32);
                    assert(dest + n <= vm.memory_len);
                    assert(src + n <= vm.memory_len);
                    assert(src + n <= dest or dest + n <= src); // overlapping
                    @memcpy((vm.memory.ptr + dest)[0..n], vm.memory.ptr + src);
                },
                .memset => {
                    const n = vm.pop(u32);
                    const value: u8 = @truncate(vm.pop(u32));
                    const dest = vm.pop(u32);
                    assert(dest + n <= vm.memory_len);
                    @memset((vm.memory.ptr + dest)[0..n], value);
                },
            }
        }
    }
};

/// fn args_sizes_get(argc: *usize, argv_buf_size: *usize) errno_t;
fn wasi_args_sizes_get(vm: *VirtualMachine, argc: u32, argv_buf_size: u32) wasi.errno_t {
    trace_log.debug("wasi_args_sizes_get argc={d} argv_buf_size={d}", .{ argc, argv_buf_size });
    mem.writeVarPackedInt(vm.memory[argc..][0..4], 0, 32, @as(u32, @intCast(vm.args.len)), .little);
    var buf_size: usize = 0;
    for (vm.args) |arg| {
        buf_size += mem.span(arg).len + 1;
    }
    mem.writeVarPackedInt(vm.memory[argv_buf_size..][0..4], 0, 32, @as(u32, @intCast(buf_size)), .little);
    return .SUCCESS;
}

/// extern fn args_get(argv: [*][*:0]u8, argv_buf: [*]u8) errno_t;
fn wasi_args_get(vm: *VirtualMachine, argv: u32, argv_buf: u32) wasi.errno_t {
    trace_log.debug("wasi_args_get argv={d} argv_buf={d}", .{ argv, argv_buf });
    var argv_buf_i: usize = 0;
    for (vm.args, 0..) |arg, arg_i| {
        // Write the arg to the buffer.
        const argv_ptr = argv_buf + argv_buf_i;
        const arg_len = mem.span(arg).len + 1;
        @memcpy(vm.memory[argv_buf + argv_buf_i ..], arg[0..arg_len]);
        argv_buf_i += arg_len;

        mem.writeVarPackedInt(vm.memory[argv + 4 * arg_i ..][0..4], 0, 32, @as(u32, @intCast(argv_ptr)), .little);
    }
    return .SUCCESS;
}

/// extern fn random_get(buf: [*]u8, buf_len: usize) errno_t;
fn wasi_random_get(vm: *VirtualMachine, buf: u32, buf_len: u32) wasi.errno_t {
    const host_buf = vm.memory[buf..][0..buf_len];
    std.crypto.random.bytes(host_buf);
    trace_log.debug("random_get {x}", .{std.fmt.fmtSliceHexLower(host_buf)});
    return .SUCCESS;
}

var preopens_buffer: [10]Preopen = undefined;
var preopens_len: usize = 0;

const Preopen = struct {
    wasi_fd: wasi.fd_t,
    name: []const u8,
    host_fd: std.posix.fd_t,
};

fn addPreopen(wasi_fd: wasi.fd_t, name: []const u8, host_fd: std.posix.fd_t) void {
    preopens_buffer[preopens_len] = .{
        .wasi_fd = wasi_fd,
        .name = name,
        .host_fd = host_fd,
    };
    preopens_len += 1;
}

fn findPreopen(wasi_fd: wasi.fd_t) ?Preopen {
    for (preopens_buffer[0..preopens_len]) |preopen| {
        if (preopen.wasi_fd == wasi_fd) {
            return preopen;
        }
    }
    return null;
}

fn toHostFd(wasi_fd: wasi.fd_t) std.posix.fd_t {
    const preopen = findPreopen(wasi_fd) orelse return wasi_fd;
    return preopen.host_fd;
}

/// fn fd_prestat_get(fd: fd_t, buf: *prestat_t) errno_t;
/// const prestat_t = extern struct {
///     pr_type: u8,
///     u: usize,
/// };
fn wasi_fd_prestat_get(vm: *VirtualMachine, fd: wasi.fd_t, buf: u32) wasi.errno_t {
    trace_log.debug("wasi_fd_prestat_get fd={d} buf={d}", .{ fd, buf });
    const preopen = findPreopen(fd) orelse return .BADF;
    mem.writePackedInt(u32, vm.memory[buf + 0 ..][0..4], 0, 0, .little);
    mem.writePackedInt(u32, vm.memory[buf + 4 ..][0..4], 0, @as(u32, @intCast(preopen.name.len)), .little);
    return .SUCCESS;
}

/// fn fd_prestat_dir_name(fd: fd_t, path: [*]u8, path_len: usize) errno_t;
fn wasi_fd_prestat_dir_name(vm: *VirtualMachine, fd: wasi.fd_t, path: u32, path_len: u32) wasi.errno_t {
    trace_log.debug("wasi_fd_prestat_dir_name fd={d} path={d} path_len={d}", .{ fd, path, path_len });
    const preopen = findPreopen(fd) orelse return .BADF;
    assert(path_len == preopen.name.len);
    @memcpy(vm.memory[path..], preopen.name);
    return .SUCCESS;
}

/// extern fn fd_close(fd: fd_t) errno_t;
fn wasi_fd_close(vm: *VirtualMachine, fd: wasi.fd_t) wasi.errno_t {
    trace_log.debug("wasi_fd_close fd={d}", .{fd});
    _ = vm;
    const host_fd = toHostFd(fd);
    std.posix.close(host_fd);
    return .SUCCESS;
}

fn wasi_fd_read(
    vm: *VirtualMachine,
    fd: wasi.fd_t,
    iovs: u32, // [*]const iovec_t
    iovs_len: u32, // usize
    nread: u32, // *usize
) wasi.errno_t {
    trace_log.debug("wasi_fd_read fd={d} iovs={d} iovs_len={d} nread={d}", .{
        fd, iovs, iovs_len, nread,
    });
    const host_fd = toHostFd(fd);
    var i: u32 = 0;
    var total_read: usize = 0;
    while (i < iovs_len) : (i += 1) {
        const ptr = mem.readVarInt(u32, vm.memory[iovs + i * 8 + 0 ..][0..4], .little);
        const len = mem.readVarInt(u32, vm.memory[iovs + i * 8 + 4 ..][0..4], .little);
        const buf = vm.memory[ptr..][0..len];
        const read = std.posix.read(host_fd, buf) catch |err| return toWasiError(err);
        trace_log.debug("read {d} bytes out of {d}", .{ read, buf.len });
        total_read += read;
        if (read != buf.len) break;
    }
    mem.writeVarPackedInt(vm.memory[nread..][0..4], 0, 32, @as(u32, @intCast(total_read)), .little);
    return .SUCCESS;
}

/// extern fn fd_write(fd: fd_t, iovs: [*]const ciovec_t, iovs_len: usize, nwritten: *usize) errno_t;
/// const ciovec_t = extern struct {
///     base: [*]const u8,
///     len: usize,
/// };
fn wasi_fd_write(vm: *VirtualMachine, fd: wasi.fd_t, iovs: u32, iovs_len: u32, nwritten: u32) wasi.errno_t {
    trace_log.debug("wasi_fd_write fd={d} iovs={d} iovs_len={d} nwritten={d}", .{
        fd, iovs, iovs_len, nwritten,
    });
    const host_fd = toHostFd(fd);
    var i: u32 = 0;
    var total_written: usize = 0;
    while (i < iovs_len) : (i += 1) {
        const ptr = mem.readVarInt(u32, vm.memory[iovs + i * 8 + 0 ..][0..4], .little);
        const len = mem.readVarInt(u32, vm.memory[iovs + i * 8 + 4 ..][0..4], .little);
        const buf = vm.memory[ptr..][0..len];
        const written = std.posix.write(host_fd, buf) catch |err| return toWasiError(err);
        total_written += written;
        if (written != buf.len) break;
    }
    mem.writeVarPackedInt(vm.memory[nwritten..][0..4], 0, 32, @as(u32, @intCast(total_written)), .little);
    return .SUCCESS;
}

fn wasi_fd_pwrite(
    vm: *VirtualMachine,
    fd: wasi.fd_t,
    iovs: u32, // [*]const ciovec_t
    iovs_len: u32, // usize
    offset: wasi.filesize_t,
    written_ptr: u32, // *usize
) wasi.errno_t {
    trace_log.debug("wasi_fd_write fd={d} iovs={d} iovs_len={d} offset={d} written_ptr={d}", .{
        fd, iovs, iovs_len, offset, written_ptr,
    });
    const host_fd = toHostFd(fd);
    var i: u32 = 0;
    var written: usize = 0;
    while (i < iovs_len) : (i += 1) {
        const ptr = mem.readVarInt(u32, vm.memory[iovs + i * 8 + 0 ..][0..4], .little);
        const len = mem.readVarInt(u32, vm.memory[iovs + i * 8 + 4 ..][0..4], .little);
        const buf = vm.memory[ptr..][0..len];
        const w = std.posix.pwrite(host_fd, buf, offset + written) catch |err| return toWasiError(err);
        written += w;
        if (w != buf.len) break;
    }
    mem.writeVarPackedInt(vm.memory[written_ptr..][0..4], 0, 32, @as(u32, @intCast(written)), .little);
    return .SUCCESS;
}

///extern fn path_open(
///    dirfd: fd_t,
///    dirflags: lookupflags_t,
///    path: [*]const u8,
///    path_len: usize,
///    oflags: oflags_t,
///    fs_rights_base: rights_t,
///    fs_rights_inheriting: rights_t,
///    fs_flags: fdflags_t,
///    fd: *fd_t,
///) errno_t;
fn wasi_path_open(
    vm: *VirtualMachine,
    dirfd: wasi.fd_t,
    dirflags: wasi.lookupflags_t,
    path: u32,
    path_len: u32,
    oflags: wasi.oflags_t,
    fs_rights_base: wasi.rights_t,
    fs_rights_inheriting: wasi.rights_t,
    fs_flags: wasi.fdflags_t,
    fd: u32,
) wasi.errno_t {
    const sub_path = vm.memory[path..][0..path_len];
    trace_log.debug("wasi_path_open dirfd={d} dirflags={d} path={s} oflags={d} fs_rights_base={d} fs_rights_inheriting={d} fs_flags={d} fd={d}", .{
        dirfd,
        @as(u32, @bitCast(dirflags)),
        sub_path,
        @as(u16, @bitCast(oflags)),
        @as(u64, @bitCast(fs_rights_base)),
        @as(u64, @bitCast(fs_rights_inheriting)),
        @as(u16, @bitCast(fs_flags)),
        fd,
    });
    const host_fd = toHostFd(dirfd);
    const flags: std.posix.O = .{
        .CREAT = oflags.CREAT,
        .DIRECTORY = oflags.DIRECTORY,
        .TRUNC = oflags.TRUNC,
        .APPEND = fs_flags.APPEND,
        .DSYNC = fs_flags.DSYNC,
        .NONBLOCK = fs_flags.NONBLOCK,
        .SYNC = fs_flags.SYNC,
        .ACCMODE = if (fs_rights_base.FD_READ and fs_rights_base.FD_WRITE) .RDWR else if (fs_rights_base.FD_READ) .RDONLY else .WRONLY,
    };

    const mode = 0o644;
    const res_fd = std.posix.openat(host_fd, sub_path, flags, mode) catch |err| return toWasiError(err);
    mem.writeVarPackedInt(vm.memory[fd..][0..4], 0, 32, res_fd, .little);
    return .SUCCESS;
}

fn wasi_path_filestat_get(
    vm: *VirtualMachine,
    fd: wasi.fd_t,
    flags: wasi.lookupflags_t,
    path: u32, // [*]const u8
    path_len: u32, // usize
    buf: u32, // *filestat_t
) wasi.errno_t {
    const sub_path = vm.memory[path..][0..path_len];
    trace_log.debug("wasi_path_filestat_get fd={d} flags={d} path={s} buf={d}", .{
        fd, @as(u32, @bitCast(flags)), sub_path, buf,
    });
    const host_fd = toHostFd(fd);
    const dir: fs.Dir = .{ .fd = host_fd };
    const stat = dir.statFile(sub_path) catch |err| return toWasiError(err);
    return finishWasiStat(vm, buf, stat);
}

/// extern fn path_create_directory(fd: fd_t, path: [*]const u8, path_len: usize) errno_t;
fn wasi_path_create_directory(vm: *VirtualMachine, fd: wasi.fd_t, path: u32, path_len: u32) wasi.errno_t {
    const sub_path = vm.memory[path..][0..path_len];
    trace_log.debug("wasi_path_create_directory fd={d} path={s}", .{ fd, sub_path });
    const host_fd = toHostFd(fd);
    const dir: fs.Dir = .{ .fd = host_fd };
    dir.makeDir(sub_path) catch |err| return toWasiError(err);
    return .SUCCESS;
}

fn wasi_path_rename(
    vm: *VirtualMachine,
    old_fd: wasi.fd_t,
    old_path_ptr: u32, // [*]const u8
    old_path_len: u32, // usize
    new_fd: wasi.fd_t,
    new_path_ptr: u32, // [*]const u8
    new_path_len: u32, // usize
) wasi.errno_t {
    const old_path = vm.memory[old_path_ptr..][0..old_path_len];
    const new_path = vm.memory[new_path_ptr..][0..new_path_len];
    trace_log.debug("wasi_path_rename old_fd={d} old_path={s} new_fd={d} new_path={s}", .{
        old_fd, old_path, new_fd, new_path,
    });
    const old_host_fd = toHostFd(old_fd);
    const new_host_fd = toHostFd(new_fd);
    std.posix.renameat(old_host_fd, old_path, new_host_fd, new_path) catch |err| return toWasiError(err);
    return .SUCCESS;
}

/// extern fn fd_filestat_get(fd: fd_t, buf: *filestat_t) errno_t;
fn wasi_fd_filestat_get(vm: *VirtualMachine, fd: wasi.fd_t, buf: u32) wasi.errno_t {
    trace_log.debug("wasi_fd_filestat_get fd={d} buf={d}", .{ fd, buf });
    const host_fd = toHostFd(fd);
    const file = fs.File{ .handle = host_fd };
    const stat = file.stat() catch |err| return toWasiError(err);
    return finishWasiStat(vm, buf, stat);
}

fn wasi_fd_filestat_set_size(vm: *VirtualMachine, fd: wasi.fd_t, size: wasi.filesize_t) wasi.errno_t {
    _ = vm;
    trace_log.debug("wasi_fd_filestat_set_size fd={d} size={d}", .{ fd, size });
    const host_fd = toHostFd(fd);
    std.posix.ftruncate(host_fd, size) catch |err| return toWasiError(err);
    return .SUCCESS;
}

/// pub extern "wasi_snapshot_preview1" fn fd_fdstat_get(fd: fd_t, buf: *fdstat_t) errno_t;
/// pub const fdstat_t = extern struct {
///     fs_filetype: filetype_t, u8
///     fs_flags: fdflags_t, u16
///     fs_rights_base: rights_t, u64
///     fs_rights_inheriting: rights_t, u64
/// };
fn wasi_fd_fdstat_get(vm: *VirtualMachine, fd: wasi.fd_t, buf: u32) wasi.errno_t {
    trace_log.debug("wasi_fd_fdstat_get fd={d} buf={d}", .{ fd, buf });
    const host_fd = toHostFd(fd);
    const file = fs.File{ .handle = host_fd };
    const stat = file.stat() catch |err| return toWasiError(err);
    const value: u16 = @intCast(@intFromEnum(toWasiFileType(stat.kind)));
    mem.writePackedInt(u16, vm.memory[buf + 0x00 ..][0..2], 0, value, .little);
    mem.writePackedInt(u16, vm.memory[buf + 0x02 ..][0..2], 0, 0, .little); // flags
    mem.writePackedInt(u64, vm.memory[buf + 0x08 ..][0..8], 0, math.maxInt(u64), .little); // rights_base
    mem.writePackedInt(u64, vm.memory[buf + 0x10 ..][0..8], 0, math.maxInt(u64), .little); // rights_inheriting
    return .SUCCESS;
}

/// extern fn clock_time_get(clock_id: clockid_t, precision: timestamp_t, timestamp: *timestamp_t) errno_t;
fn wasi_clock_time_get(vm: *VirtualMachine, clock_id: wasi.clockid_t, precision: wasi.timestamp_t, timestamp: u32) wasi.errno_t {
    //const host_clock_id = toHostClockId(clock_id);
    _ = precision;
    _ = clock_id;
    const wasi_ts = toWasiTimestamp(std.time.nanoTimestamp());
    mem.writeVarPackedInt(vm.memory[timestamp..][0..8], 0, 64, wasi_ts, .little);
    return .SUCCESS;
}

///pub extern "wasi_snapshot_preview1" fn debug(string: [*:0]const u8, x: u64) void;
fn wasi_debug(vm: *VirtualMachine, text: u32, n: u64) void {
    const s = mem.sliceTo(vm.memory[text..], 0);
    trace_log.debug("wasi_debug: '{s}' number={d} {x}", .{ s, n, n });
}

/// pub extern "wasi_snapshot_preview1" fn debug_slice(ptr: [*]const u8, len: usize) void;
fn wasi_debug_slice(vm: *VirtualMachine, ptr: u32, len: u32) void {
    const s = vm.memory[ptr..][0..len];
    trace_log.debug("wasi_debug_slice: '{s}'", .{s});
}

fn toWasiTimestamp(ns: i128) u64 {
    return @truncate(@as(u128, @intCast(ns)));
}

fn toWasiError(err: anyerror) wasi.errno_t {
    trace_log.warn("wasi error: {s}", .{@errorName(err)});
    return switch (err) {
        error.AccessDenied => .ACCES,
        error.DiskQuota => .DQUOT,
        error.InputOutput => .IO,
        error.FileTooBig => .FBIG,
        error.NoSpaceLeft => .NOSPC,
        error.BrokenPipe => .PIPE,
        error.NotOpenForWriting => .BADF,
        error.SystemResources => .NOMEM,
        error.FileNotFound => .NOENT,
        error.PathAlreadyExists => .EXIST,
        else => std.debug.panic("unexpected error: {s}", .{@errorName(err)}),
    };
}

fn toWasiFileType(kind: fs.File.Kind) wasi.filetype_t {
    return switch (kind) {
        .block_device => .BLOCK_DEVICE,
        .character_device => .CHARACTER_DEVICE,
        .directory => .DIRECTORY,
        .sym_link => .SYMBOLIC_LINK,
        .file => .REGULAR_FILE,
        .unknown => .UNKNOWN,

        .named_pipe,
        .unix_domain_socket,
        .whiteout,
        .door,
        .event_port,
        => .UNKNOWN,
    };
}

/// const filestat_t = extern struct {
///     dev: device_t, u64
///     ino: inode_t, u64
///     filetype: filetype_t, u8
///     nlink: linkcount_t, u64
///     size: filesize_t, u64
///     atim: timestamp_t, u64
///     mtim: timestamp_t, u64
///     ctim: timestamp_t, u64
/// };
fn finishWasiStat(vm: *VirtualMachine, buf: u32, stat: fs.File.Stat) wasi.errno_t {
    mem.writePackedInt(u64, vm.memory[buf + 0x00 ..][0..8], 0, 0, .little); // device
    mem.writePackedInt(u64, vm.memory[buf + 0x08 ..][0..8], 0, stat.inode, .little);
    mem.writePackedInt(u64, vm.memory[buf + 0x10 ..][0..8], 0, @intFromEnum(toWasiFileType(stat.kind)), .little);
    mem.writePackedInt(u64, vm.memory[buf + 0x18 ..][0..8], 0, 1, .little); // nlink
    mem.writePackedInt(u64, vm.memory[buf + 0x20 ..][0..8], 0, stat.size, .little);
    mem.writePackedInt(u64, vm.memory[buf + 0x28 ..][0..8], 0, toWasiTimestamp(stat.atime), .little);
    mem.writePackedInt(u64, vm.memory[buf + 0x30 ..][0..8], 0, toWasiTimestamp(stat.mtime), .little);
    mem.writePackedInt(u64, vm.memory[buf + 0x38 ..][0..8], 0, toWasiTimestamp(stat.ctime), .little);
    return .SUCCESS;
}
