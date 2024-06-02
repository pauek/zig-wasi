//! copied from lib/std/io/c_writer.zig, unaudited

const std = @import("std");

pub const ModuleReader = std.io.Reader(*std.c.FILE, std.fs.File.ReadError, c_reader_read);

pub fn makeModuleReader(wasm_file: [*:0]const u8) !ModuleReader {
    const module_file = std.c.fopen(wasm_file, "rb") orelse return error.FileNotFound;
    // defer _ = std.c.fclose(module_file);
    return .{ .context = module_file };
}



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
