const std = @import("std");
const wasm = std.wasm;
const math = std.math;
const assert = std.debug.assert;
const decode_log = std.log.scoped(.decode);
const stats_log = std.log.scoped(.stats);
const trace_log = std.log.scoped(.trace);
const cpu_log = std.log.scoped(.cpu);
const func_log = std.log.scoped(.func);
const leb = std.leb;
const mem = std.mem;

pub const types = @import("./types.zig");

pub const Opcode = types.Opcode;
pub const ProgramCounter = types.ProgramCounter;
pub const Function = types.Function;
pub const TypeInfo = types.TypeInfo;
pub const Import = types.Import;
pub const StackInfo = types.StackInfo;
pub const Label = types.Label;

const MAX_MEMORY = 3 * 1024 * 1024; // 3 MiB

pub const VirtualMachine = struct {
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

    pub fn decodeCode(
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

    pub fn call(vm: *VirtualMachine, func: *const Function) void {
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

    fn callImport(_: *VirtualMachine, import: *const Import) void {
        switch (import.mod) {}
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

    pub fn pop(vm: *VirtualMachine, comptime T: type) T {
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

    pub fn run(vm: *VirtualMachine) noreturn {
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

pub fn makeVirtualMachine(allocator: std.mem.Allocator) !VirtualMachine {
    var vm: VirtualMachine = undefined;
    vm.memory = try allocator.alloc(u8, MAX_MEMORY);
    vm.stack = try allocator.alloc(u32, 100_000);
    vm.stack_top = 0;
    return vm;
}
