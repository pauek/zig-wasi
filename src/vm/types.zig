const std = @import("std");
const wasm = std.wasm;
const math = std.math;
const assert = std.debug.assert;

pub const Opcode = enum {
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

    pub const wrap_32_64 = Opcode.drop_32;
    pub const zext_64_32 = Opcode.const_0_32;
    pub const last = Opcode.memset;
};

pub const ProgramCounter = struct { opcode: u32, operand: u32 };

pub const Mutability = enum { @"const", @"var" };

pub const TypeInfo = struct {
    pub const ParamTypes = std.StaticBitSet(1 << 5);
    pub const ResultTypes = std.StaticBitSet(1);

    param_count: u32,
    param_types: ParamTypes,
    result_count: u32,
    result_types: ResultTypes,
};

pub const Function = struct {
    id: u32,
    entry_pc: ProgramCounter,
    type_idx: u32,
    locals_size: u32,
};

pub const Import = struct {
    pub const Mod = enum {
        // wasi_snapshot_preview1,
    };
    pub const Name = enum {
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

pub const Label = struct {
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

    pub fn operandCount(self: Label) u32 {
        return if (self.opcode == .loop) self.type_info.param_count else self.type_info.result_count;
    }

    pub fn operandType(self: Label, index: u32) StackInfo.EntryType {
        return StackInfo.EntryType.fromBool(if (self.opcode == .loop)
            self.type_info.param_types.isSet(index)
        else
            self.type_info.result_types.isSet(index));
    }
};

pub const StackInfo = struct {
    // f32 is stored as i32 and f64 is stored as i64
    pub const EntryType = enum {
        i32,
        i64,

        pub fn size(self: EntryType) u32 {
            return switch (self) {
                .i32 => 1,
                .i64 => 2,
            };
        }

        pub fn toBool(self: EntryType) bool {
            return self != .i32;
        }

        pub fn fromBool(self: bool) EntryType {
            return @enumFromInt(@intFromBool(self));
        }
    };
    const max_stack_depth = 1 << 12;

    top_index: u32 = 0,
    top_offset: u32 = 0,
    types: std.StaticBitSet(max_stack_depth) = undefined,
    offsets: [max_stack_depth]u32 = undefined,

    pub fn push(self: *StackInfo, entry_type: EntryType) void {
        self.types.setValue(self.top_index, entry_type.toBool());
        self.offsets[self.top_index] = self.top_offset;
        self.top_index += 1;
        self.top_offset += entry_type.size();
    }

    pub fn pop(self: *StackInfo, entry_type: EntryType) void {
        assert(self.top() == entry_type);
        self.top_index -= 1;
        self.top_offset -= entry_type.size();
        assert(self.top_offset == self.offsets[self.top_index]);
    }

    pub fn top(self: StackInfo) EntryType {
        return EntryType.fromBool(self.types.isSet(self.top_index - 1));
    }

    pub fn local(self: StackInfo, local_idx: u32) EntryType {
        return EntryType.fromBool(self.types.isSet(local_idx));
    }
};
