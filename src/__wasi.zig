const std = @import("std");
const VirtualMachine = @import("./vm.zig").VirtualMachine;
const wasi = std.wasi;
const mem = std.mem;
const trace_log = std.log.scoped(.trace);
const fs = std.fs;
const assert = std.debug.assert;
const math = std.math;

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
