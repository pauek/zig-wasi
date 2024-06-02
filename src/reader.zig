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
    c_reader: CReader,

    fn advance_to_section(self: *ModuleReader, section: wasm.Section) !void {
        const section_type: wasm.Section = @enumFromInt(try self.c_reader.readByte());
        while (section_type != section)
            assert(fseek(
                self.c_reader.context,
                @as(c_long, try leb.readULEB128(u32, self.c_reader)),
                .CUR,
            ) == 0);
        _ = try leb.readULEB128(u32, self.c_reader);
    }

    pub inline fn readNoEof(self: *ModuleReader, buf: []u8) !void {
        try self.c_reader.readNoEof(buf);
    }

    pub inline fn readVarInt(self: *ModuleReader, comptime ReturnType: type, endian: std.builtin.Endian, size: usize) !ReturnType {
        return self.c_reader.readVarInt(ReturnType, endian, size);
    }

    pub fn read(self: *ModuleReader, allocator: std.mem.Allocator, vm: *VirtualMachine) !u32 {
        var start_fn_idx: u32 = undefined;

        var magic: [4]u8 = undefined;
        try self.readNoEof(&magic);
        if (!mem.eql(u8, &magic, "\x00asm")) return error.NotWasm;

        const version = try self.readVarInt(u32, std.builtin.Endian.little, 1);
        if (version != 1) return error.BadWasmVersion;

        try self.advance_to_section(.type);

        var max_param_count: u64 = 0;
        vm.types = try allocator.alloc(VM.TypeInfo, try leb.readULEB128(u32, self.c_reader));
        for (vm.types) |*@"type"| {
            assert(try leb.readILEB128(i33, self.c_reader) == -0x20);

            @"type".param_count = try leb.readULEB128(u32, self.c_reader);
            assert(@"type".param_count <= 32);
            @"type".param_types = VM.TypeInfo.ParamTypes.initEmpty();
            max_param_count = @max(@"type".param_count, max_param_count);
            var param_index: u32 = 0;
            while (param_index < @"type".param_count) : (param_index += 1) {
                const param_type = try leb.readILEB128(i33, self.c_reader);
                @"type".param_types.setValue(param_index, switch (param_type) {
                    -1, -3 => false,
                    -2, -4 => true,
                    else => unreachable,
                });
            }

            @"type".result_count = try leb.readULEB128(u32, self.c_reader);
            assert(@"type".result_count <= 1);
            @"type".result_types = VM.TypeInfo.ResultTypes.initEmpty();
            var result_index: u32 = 0;
            while (result_index < @"type".result_count) : (result_index += 1) {
                const result_type = try leb.readILEB128(i33, self.c_reader);
                @"type".result_types.setValue(result_index, switch (result_type) {
                    -1, -3 => false,
                    -2, -4 => true,
                    else => unreachable,
                });
            }
        }

        try self.advance_to_section(.import);
        {
            vm.imports = try allocator.alloc(VM.Import, try leb.readULEB128(u32, self.c_reader));

            comptime var max_str_len: usize = 0;
            inline for (.{ VM.Import.Mod, VM.Import.Name }) |Enum| {
                inline for (comptime std.meta.fieldNames(Enum)) |str| {
                    max_str_len = @max(str.len, max_str_len);
                }
            }
            var str_buf: [max_str_len]u8 = undefined;

            for (vm.imports) |*import| {
                const mod = str_buf[0..try leb.readULEB128(u32, self.c_reader)];
                try self.readNoEof(mod);
                import.mod = std.meta.stringToEnum(VM.Import.Mod, mod).?;

                const name = str_buf[0..try leb.readULEB128(u32, self.c_reader)];
                try self.readNoEof(name);
                import.name = std.meta.stringToEnum(VM.Import.Name, name).?;

                const kind: wasm.ExternalKind = @enumFromInt(try self.c_reader.readByte());
                const idx = try leb.readULEB128(u32, self.c_reader);
                switch (kind) {
                    .function => import.type_idx = idx,
                    .table, .memory, .global => unreachable,
                }
            }
        }

        try self.advance_to_section(.function);
        vm.functions = try allocator.alloc(VM.Function, try leb.readULEB128(u32, self.c_reader));
        for (vm.functions, 0..) |*function, func_idx| {
            const len: u32 = @truncate(vm.imports.len);
            const idx: u32 = @truncate(func_idx);
            function.id = len + idx;
            function.type_idx = try leb.readULEB128(u32, self.c_reader);
        }

        try self.advance_to_section(.table);
        {
            const table_count = try leb.readULEB128(u32, self.c_reader);
            if (table_count == 1) {
                assert(try leb.readILEB128(i33, self.c_reader) == -0x10);
                const limits_kind = try self.c_reader.readByte();
                vm.table = try allocator.alloc(u32, try leb.readULEB128(u32, self.c_reader));
                switch (limits_kind) {
                    0x00 => {},
                    0x01 => _ = try leb.readULEB128(u32, self.c_reader),
                    else => unreachable,
                }
            } else assert(table_count == 0);
        }

        try self.advance_to_section(.memory);
        {
            assert(try leb.readULEB128(u32, self.c_reader) == 1);
            const limits_kind = try self.c_reader.readByte();
            vm.memory_len = try leb.readULEB128(u32, self.c_reader) * wasm.page_size;
            switch (limits_kind) {
                0x00 => {},
                0x01 => _ = try leb.readULEB128(u32, self.c_reader),
                else => unreachable,
            }
        }

        try self.advance_to_section(.global);
        vm.globals = try allocator.alloc(u32, try leb.readULEB128(u32, self.c_reader));
        for (vm.globals) |*global| {
            assert(try leb.readILEB128(i33, self.c_reader) == -1);
            _ = try self.c_reader.readByte();
            const global_type: wasm.Opcode = @enumFromInt(try self.c_reader.readByte());
            assert(global_type == .i32_const);
            global.* = @intCast(try leb.readILEB128(i32, self.c_reader));
            const opcode: wasm.Opcode = @enumFromInt(try self.c_reader.readByte());
            assert(opcode == .end);
        }

        try self.advance_to_section(.@"export");
        {
            var found_start_fn = false;
            const start_name = "_start";
            var str_buf: [start_name.len]u8 = undefined;

            var export_count = try leb.readULEB128(u32, self.c_reader);
            while (export_count > 0) : (export_count -= 1) {
                const name_len = try leb.readULEB128(u32, self.c_reader);
                var is_start_fn = false;
                if (name_len == start_name.len) {
                    try self.readNoEof(&str_buf);
                    is_start_fn = mem.eql(u8, &str_buf, start_name);
                    found_start_fn = found_start_fn or is_start_fn;
                } else assert(fseek(self.c_reader.context, @as(c_long, name_len), .CUR) == 0);

                const kind: wasm.ExternalKind = @enumFromInt(try self.c_reader.readByte());
                const idx = try leb.readULEB128(u32, self.c_reader);
                switch (kind) {
                    .function => if (is_start_fn) {
                        start_fn_idx = idx;
                    },
                    .table, .memory, .global => {},
                }
            }
            assert(found_start_fn);
        }

        try self.advance_to_section(.element);
        {
            var segment_count = try leb.readULEB128(u32, self.c_reader);
            while (segment_count > 0) : (segment_count -= 1) {
                const flags: u32 = @intCast(try leb.readULEB128(u32, self.c_reader));
                assert(flags & 0b001 == 0b000);
                if (flags & 0b010 == 0b010) assert(try leb.readULEB128(u32, self.c_reader) == 0);

                const opcode: wasm.Opcode = @enumFromInt(try self.c_reader.readByte());
                assert(opcode == .i32_const);
                var offset: u32 = @intCast(try leb.readILEB128(i32, self.c_reader));
                const end: wasm.Opcode = @enumFromInt(try self.c_reader.readByte());
                assert(end == .end);

                const element_type = if (flags & 0b110 != 0b110) idx: {
                    if (flags & 0b010 == 0b010) assert(try self.c_reader.readByte() == 0x00);
                    break :idx -0x10;
                } else try leb.readILEB128(i33, self.c_reader);
                assert(element_type == -0x10);

                var element_count = try leb.readULEB128(u32, self.c_reader);
                while (element_count > 0) : ({
                    offset += 1;
                    element_count -= 1;
                }) {
                    if (flags & 0b010 == 0b010)
                        assert(try self.c_reader.readByte() == 0xD2);
                    vm.table[offset] = try leb.readULEB128(u32, self.c_reader);
                    if (flags & 0b010 == 0b010) {
                        const end_opcode: wasm.Opcode = @enumFromInt(try self.c_reader.readByte());
                        assert(end_opcode == .end);
                    }
                }
            }
        }

        try self.advance_to_section(.code);
        var max_frame_size: u64 = 0;
        {
            vm.opcodes = try allocator.alloc(u8, 5000000);
            vm.operands = try allocator.alloc(u32, 5000000);

            assert(try leb.readULEB128(u32, self.c_reader) == vm.functions.len);
            var pc = VM.ProgramCounter{ .opcode = 0, .operand = 0 };
            var stack: VM.StackInfo = undefined;
            for (vm.functions) |*func| {
                _ = try leb.readULEB128(u32, self.c_reader);

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

                var local_sets_count = try leb.readULEB128(u32, self.c_reader);
                while (local_sets_count > 0) : (local_sets_count -= 1) {
                    var local_set_count = try leb.readULEB128(u32, self.c_reader);
                    const local_type = switch (try leb.readILEB128(i33, self.c_reader)) {
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

            stats_log.debug("{} opcodes", .{pc.opcode});
            stats_log.debug("{} operands", .{pc.operand});
            for (opcode_counts, 0..) |opcode_count, opcode| {
                const last_opcode: usize = @intFromEnum(VM.Opcode.last);
                if (opcode > last_opcode) continue;
                const opcode_enum: VM.Opcode = @enumFromInt(opcode);
                stats_log.debug("{} {s}", .{ opcode_count, @tagName(opcode_enum) });
            }
        }

        try self.advance_to_section(.data);
        {
            var segment_count = try leb.readULEB128(u32, self.c_reader);
            while (segment_count > 0) : (segment_count -= 1) {
                const flags = @as(u32, try leb.readULEB128(u32, self.c_reader));
                assert(flags & 0b001 == 0b000);
                if (flags & 0b010 == 0b010) assert(try leb.readULEB128(u32, self.c_reader) == 0);

                const i32_const: wasm.Opcode = @enumFromInt(try self.c_reader.readByte());
                assert(i32_const == .i32_const);

                const offset = @as(u32, @bitCast(try leb.readILEB128(i32, self.c_reader)));
                const end: wasm.Opcode = @enumFromInt(try self.c_reader.readByte());
                assert(end == .end);

                const length = try leb.readULEB128(u32, self.c_reader);
                try self.readNoEof(vm.memory[offset..][0..length]);
            }
        }

        return start_fn_idx;
    }
};

pub fn makeModuleReader(wasm_file: [*:0]const u8) !ModuleReader {
    const module_file = std.c.fopen(wasm_file, "rb") orelse return error.FileNotFound;
    // defer _ = std.c.fclose(module_file);
    return .{ .c_reader = .{ .context = module_file } };
}
