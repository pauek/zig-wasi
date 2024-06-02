const std = @import("std");
const mem = std.mem;
const wasm = std.wasm;
const assert = std.debug.assert;
const leb = std.leb;
const VM = @import("./vm/vm.zig");
const VirtualMachine = VM.VirtualMachine;
const decode_log = std.log.scoped(.decode);
const stats_log = std.log.scoped(.stats);
const trace_log = std.log.scoped(.trace);
const cpu_log = std.log.scoped(.cpu);
const func_log = std.log.scoped(.func);

const SEEK = enum(c_int) { SET, CUR, END };

pub extern "c" fn fseek(stream: *std.c.FILE, offset: c_long, whence: SEEK) c_int;

fn c_reader_read(c_file: *std.c.FILE, bytes: []u8) std.fs.File.ReadError!usize {
    const amt_read = std.c.fread(bytes.ptr, 1, bytes.len, c_file);
    if (amt_read >= 0) return amt_read;
    const errno: std.os.E = @enumFromInt(std.c._errno().*);
    switch (errno) {
        .SUCCESS => unreachable,
        .INVAL => unreachable,
        .FAULT => unreachable,
        .AGAIN => unreachable, // this is a blocking API
        .BADF => unreachable, // always a race condition
        .DESTADDRREQ => unreachable, // connect was never called
        .DQUOT => return error.DiskQuota,
        .FBIG => return error.FileTooBig,
        .IO => return error.InputOutput,
        .NOSPC => return error.NoSpaceLeft,
        .PERM => return error.AccessDenied,
        .PIPE => return error.BrokenPipe,
        else => |err| return std.os.unexpectedErrno(err),
    }
}

const CReader = std.io.Reader(*std.c.FILE, std.fs.File.ReadError, c_reader_read);

pub const ModuleReader = struct {
    allocator: std.mem.Allocator,
    c_reader: CReader,
    start_fn_idx: u32 = undefined,

    fn advance_to_section(self: *ModuleReader, section: wasm.Section) !void {
        const section_type: wasm.Section = @enumFromInt(try self.readByte());
        while (section_type != section)
            assert(fseek(
                self.c_reader.context,
                @as(c_long, try self.readULEB128(u32)),
                .CUR,
            ) == 0);
        _ = try leb.readULEB128(u32, self.c_reader);
    }

    inline fn readNoEof(self: *ModuleReader, buf: []u8) !void {
        try self.c_reader.readNoEof(buf);
    }

    inline fn readVarInt(self: *ModuleReader, comptime T: type, endian: std.builtin.Endian, size: usize) !T {
        return self.c_reader.readVarInt(T, endian, size);
    }

    inline fn readULEB128(self: *ModuleReader, comptime T: type) !T {
        return try leb.readULEB128(T, self.c_reader);
    }

    inline fn readILEB128(self: *ModuleReader, comptime T: type) !T {
        return try leb.readILEB128(T, self.c_reader);
    }

    inline fn readLittleEndian(self: *ModuleReader, comptime T: type) !T {
        return try self.readVarInt(T, std.builtin.Endian.little, @sizeOf(T));
    }

    inline fn readByte(self: *ModuleReader) !u8 {
        return try self.c_reader.readByte();
    }

    fn readPreamble(self: *ModuleReader) !void {
        var magic: [4]u8 = undefined;
        try self.readNoEof(&magic);
        if (!mem.eql(u8, &magic, "\x00asm")) {
            return error.NotWasm;
        }

        const version = try self.readLittleEndian(u32);
        if (version != 1) {
            return error.BadWasmVersion;
        }
    }

    fn readTypes(self: *ModuleReader, vm: *VirtualMachine) !void {
        try self.advance_to_section(.type);

        var max_param_count: u64 = 0;
        vm.types = try self.allocator.alloc(VM.TypeInfo, try self.readULEB128(u32));
        for (vm.types) |*@"type"| {
            assert(try self.readILEB128(i33) == -0x20);

            @"type".param_count = try self.readULEB128(u32);
            assert(@"type".param_count <= 32);
            @"type".param_types = VM.TypeInfo.ParamTypes.initEmpty();
            max_param_count = @max(@"type".param_count, max_param_count);
            var param_index: u32 = 0;
            while (param_index < @"type".param_count) : (param_index += 1) {
                const param_type = try self.readILEB128(i33);
                @"type".param_types.setValue(param_index, switch (param_type) {
                    -1, -3 => false,
                    -2, -4 => true,
                    else => unreachable,
                });
            }

            @"type".result_count = try self.readULEB128(u32);
            assert(@"type".result_count <= 1);
            @"type".result_types = VM.TypeInfo.ResultTypes.initEmpty();
            var result_index: u32 = 0;
            while (result_index < @"type".result_count) : (result_index += 1) {
                const result_type = try self.readILEB128(i33);
                @"type".result_types.setValue(result_index, switch (result_type) {
                    -1, -3 => false,
                    -2, -4 => true,
                    else => unreachable,
                });
            }
        }
    }

    fn readImports(self: *ModuleReader, vm: *VirtualMachine) !void {
        try self.advance_to_section(.import);

        vm.imports = try self.allocator.alloc(VM.Import, try self.readULEB128(u32));

        comptime var max_str_len: usize = 0;
        inline for (.{ VM.Import.Mod, VM.Import.Name }) |Enum| {
            inline for (comptime std.meta.fieldNames(Enum)) |str| {
                max_str_len = @max(str.len, max_str_len);
            }
        }
        var str_buf: [max_str_len]u8 = undefined;

        for (vm.imports) |*import| {
            const mod = str_buf[0..try self.readULEB128(u32)];
            try self.readNoEof(mod);
            import.mod = std.meta.stringToEnum(VM.Import.Mod, mod).?;

            const name = str_buf[0..try self.readULEB128(u32)];
            try self.readNoEof(name);
            import.name = std.meta.stringToEnum(VM.Import.Name, name).?;

            const kind: wasm.ExternalKind = @enumFromInt(try self.readByte());
            const idx = try self.readULEB128(u32);
            switch (kind) {
                .function => import.type_idx = idx,
                .table, .memory, .global => unreachable,
            }
        }
    }

    fn readFunctions(self: *ModuleReader, vm: *VirtualMachine) !void {
        try self.advance_to_section(.function);
        const num_functions = try self.readULEB128(u32);
        vm.functions = try self.allocator.alloc(VM.Function, num_functions);
        for (vm.functions, 0..) |*function, func_idx| {
            const len: u32 = @truncate(vm.imports.len);
            const idx: u32 = @truncate(func_idx);
            function.id = len + idx;
            function.type_idx = try self.readULEB128(u32);
        }
    }

    fn readTables(self: *ModuleReader, vm: *VirtualMachine) !void {
        try self.advance_to_section(.table);

        const table_count = try self.readULEB128(u32);
        if (table_count == 1) {
            assert(try self.readILEB128(i33) == -0x10);
            const limits_kind = try self.readByte();
            vm.table = try self.allocator.alloc(u32, try self.readULEB128(u32));
            switch (limits_kind) {
                0x00 => {},
                0x01 => _ = try self.readULEB128(u32),
                else => unreachable,
            }
        } else assert(table_count == 0);
    }

    fn readMemories(self: *ModuleReader, vm: *VirtualMachine) !void {
        try self.advance_to_section(.memory);

        assert(try self.readULEB128(u32) == 1);
        const limits_kind = try self.readByte();
        vm.memory_len = try self.readULEB128(u32) * wasm.page_size;
        switch (limits_kind) {
            0x00 => {},
            0x01 => _ = try self.readULEB128(u32),
            else => unreachable,
        }
    }

    fn readGlobals(self: *ModuleReader, vm: *VirtualMachine) !void {
        try self.advance_to_section(.global);
        const num_globals = try self.readULEB128(u32);
        vm.globals = try self.allocator.alloc(u32, num_globals);
        for (vm.globals) |*global| {
            assert(try self.readILEB128(i33) == -1);
            _ = try self.readByte();
            const global_type: wasm.Opcode = @enumFromInt(try self.readByte());
            assert(global_type == .i32_const);
            global.* = @intCast(try self.readILEB128(i32));
            const opcode: wasm.Opcode = @enumFromInt(try self.readByte());
            assert(opcode == .end);
        }
    }

    fn readExports(self: *ModuleReader) !void {
        try self.advance_to_section(.@"export");

        var found_start_fn = false;
        const start_name = "_start";
        var str_buf: [start_name.len]u8 = undefined;

        var export_count = try self.readULEB128(u32);
        while (export_count > 0) : (export_count -= 1) {
            const name_len = try self.readULEB128(u32);
            var is_start_fn = false;
            if (name_len == start_name.len) {
                try self.readNoEof(&str_buf);
                is_start_fn = mem.eql(u8, &str_buf, start_name);
                found_start_fn = found_start_fn or is_start_fn;
            } else assert(fseek(self.c_reader.context, @as(c_long, name_len), .CUR) == 0);

            const kind: wasm.ExternalKind = @enumFromInt(try self.readByte());
            const idx = try self.readULEB128(u32);
            switch (kind) {
                .function => if (is_start_fn) {
                    self.start_fn_idx = idx;
                },
                .table, .memory, .global => {},
            }
        }
        assert(found_start_fn);
    }

    fn readElements(self: *ModuleReader, vm: *VirtualMachine) !void {
        try self.advance_to_section(.element);

        var segment_count = try self.readULEB128(u32);
        while (segment_count > 0) : (segment_count -= 1) {
            const flags: u32 = @intCast(try self.readULEB128(u32));
            assert(flags & 0b001 == 0b000);
            if (flags & 0b010 == 0b010) assert(try self.readULEB128(u32) == 0);

            const opcode: wasm.Opcode = @enumFromInt(try self.readByte());
            assert(opcode == .i32_const);
            var offset: u32 = @intCast(try self.readILEB128(i32));
            const end: wasm.Opcode = @enumFromInt(try self.readByte());
            assert(end == .end);

            const element_type = if (flags & 0b110 != 0b110) idx: {
                if (flags & 0b010 == 0b010) assert(try self.readByte() == 0x00);
                break :idx -0x10;
            } else try self.readILEB128(i33);
            assert(element_type == -0x10);

            var element_count = try self.readULEB128(u32);
            while (element_count > 0) : ({
                offset += 1;
                element_count -= 1;
            }) {
                if (flags & 0b010 == 0b010)
                    assert(try self.readByte() == 0xD2);
                vm.table[offset] = try self.readULEB128(u32);
                if (flags & 0b010 == 0b010) {
                    const end_opcode: wasm.Opcode = @enumFromInt(try self.readByte());
                    assert(end_opcode == .end);
                }
            }
        }
    }

    fn readCode(self: *ModuleReader, vm: *VirtualMachine) !void {
        try self.advance_to_section(.code);
        var max_frame_size: u64 = 0;

        vm.opcodes = try self.allocator.alloc(u8, 5000000);
        vm.operands = try self.allocator.alloc(u32, 5000000);

        assert(try self.readULEB128(u32) == vm.functions.len);
        var pc = VM.ProgramCounter{ .opcode = 0, .operand = 0 };
        var stack: VM.StackInfo = undefined;
        for (vm.functions) |*func| {
            _ = try self.readULEB128(u32);

            stack = .{};
            const type_info = vm.types[func.type_idx];
            var param_i: u32 = 0;
            while (param_i < type_info.param_count) : (param_i += 1) {
                const entry_type: VM.StackInfo.EntryType = @enumFromInt(
                    @intFromBool(type_info.param_types.isSet(param_i)),
                );
                stack.push(entry_type);
            }
            const params_size = stack.top_offset;

            var local_sets_count = try self.readULEB128(u32);
            while (local_sets_count > 0) : (local_sets_count -= 1) {
                var local_set_count = try self.readULEB128(u32);
                const local_type = switch (try self.readILEB128(i33)) {
                    -1, -3 => VM.StackInfo.EntryType.i32,
                    -2, -4 => VM.StackInfo.EntryType.i64,
                    else => unreachable,
                };
                while (local_set_count > 0) : (local_set_count -= 1)
                    stack.push(local_type);
            }
            func.locals_size = stack.top_offset - params_size;
            max_frame_size = @max(params_size + func.locals_size, max_frame_size);

            func.entry_pc = pc;
            decode_log.debug("decoding func id {d} with pc {d}:{d}", .{ func.id, pc.opcode, pc.operand });
            try vm.decodeCode(self.c_reader, type_info, &pc, &stack);
        }

        var opcode_counts = [1]u64{0} ** 0x100;
        var prefix: ?VM.types.Opcode = null;
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

        for (opcode_counts, 0..) |opcode_count, opcode| {
            const last_opcode: usize = @intFromEnum(VM.Opcode.last);
            if (opcode > last_opcode) continue;
            const opcode_enum: VM.Opcode = @enumFromInt(opcode);
            stats_log.debug("{} {s}", .{ opcode_count, @tagName(opcode_enum) });
        }
    }

    fn readData(self: *ModuleReader, vm: *VirtualMachine) !void {
        try self.advance_to_section(.data);
        var segment_count = try self.readULEB128(u32);
        while (segment_count > 0) : (segment_count -= 1) {
            const flags = @as(u32, try self.readULEB128(u32));
            assert(flags & 0b001 == 0b000);
            if (flags & 0b010 == 0b010) assert(try self.readULEB128(u32) == 0);

            const i32_const: wasm.Opcode = @enumFromInt(try self.readByte());
            assert(i32_const == .i32_const);

            const offset = @as(u32, @bitCast(try self.readILEB128(i32)));
            const end: wasm.Opcode = @enumFromInt(try self.readByte());
            assert(end == .end);

            const length = try self.readULEB128(u32);
            try self.readNoEof(vm.memory[offset..][0..length]);
        }
    }

    pub fn read(self: *ModuleReader, vm: *VirtualMachine) !u32 {
        try self.readPreamble();
        try self.readTypes(vm);
        try self.readImports(vm);
        try self.readFunctions(vm);
        try self.readTables(vm);
        try self.readMemories(vm);
        try self.readGlobals(vm);
        try self.readExports();
        try self.readElements(vm);
        try self.readCode(vm);
        try self.readData(vm);

        return self.start_fn_idx;
    }

    pub fn dispose(self: *ModuleReader) void {
        _ = std.c.fclose(self.c_reader.context);
    }
};

pub fn makeModuleReader(allocator: std.mem.Allocator, wasm_file: [*:0]const u8) !ModuleReader {
    const module_file = std.c.fopen(wasm_file, "rb") orelse return error.FileNotFound;
    return .{
        .c_reader = .{
            .context = module_file,
        },
        .allocator = allocator,
    };
}
