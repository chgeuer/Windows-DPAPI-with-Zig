const std = @import("std");
const win = std.os.windows;

// C:\ProgramData\chocolatey\lib\zig\tools\zig-windows-x86_64-0.11.0\lib\libc\include\any-windows-any\dpapi.h
// C:\Program Files\Microsoft Visual Studio\2022\Enterprise\SDK\ScopeCppSDK\vc15\SDK\include\um\dpapi.h
// C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um\dpapi.h
const CRYPTPROTECT_UI_FORBIDDEN: win.DWORD = 0x1;

// https://learn.microsoft.com/en-us/windows/win32/api/dpapi/ns-dpapi-cryptprotect_promptstruct
const CRYPTPROTECT_PROMPTSTRUCT = extern struct {
    cbSize: win.DWORD, //        DWORD   cbSize;
    dwPromptFlags: win.DWORD, // DWORD   dwPromptFlags;
    hwndApp: win.HWND, //        HWND    hwndApp;
    szPrompt: *win.LPCWSTR, //   LPCWSTR szPrompt;
};

// https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptunprotectdata
pub extern "crypt32" fn CryptUnprotectData(
    pDataIn: *Blob,
    ppszDataDescr: ?*win.LPWSTR,
    pOptionalEntropy: ?*Blob,
    pvReserved: ?*win.PVOID,
    pPromptStruct: ?*CRYPTPROTECT_PROMPTSTRUCT,
    dwFlags: win.DWORD,
    pDataOut: *Blob,
) callconv(win.WINAPI) win.BOOL;

// https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata
pub extern "crypt32" fn CryptProtectData(
    pDataIn: *Blob,
    ppszDataDescr: ?*win.LPWSTR,
    pOptionalEntropy: ?*Blob,
    pvReserved: ?*win.PVOID,
    pPromptStruct: ?*CRYPTPROTECT_PROMPTSTRUCT,
    dwFlags: win.DWORD,
    pDataOut: *Blob,
) callconv(win.WINAPI) win.BOOL;

const Blob = extern struct {
    cbData: win.DWORD,
    pbData: [*]win.BYTE,

    pub fn new(buffer: []u8) Blob {
        return Blob{
            .cbData = @as(win.DWORD, @intCast(buffer.len)),
            .pbData = @ptrCast(buffer),
        };
    }

    pub fn deinit(self: *Blob, allocator: std.mem.Allocator) void {
        _ = std.os.windows.kernel32.LocalFree(self.pbData);
        allocator.destroy(self);
    }

    pub fn slice(self: Blob) []const u8 {
        return self.pbData[0..self.cbData];
    }
};

pub fn dpapi_wrap(buffer: []u8, allocator: std.mem.Allocator) !?[]u8 {
    var input: Blob = Blob.new(buffer);

    var output: *Blob = try allocator.create(Blob);
    defer output.deinit(allocator);

    var descOut: win.LPWSTR = undefined;

    var success = CryptProtectData(&input, &descOut, null, null, null, CRYPTPROTECT_UI_FORBIDDEN, output);
    if (success == 1) {
        const result: []u8 = try allocator.alloc(u8, output.*.cbData);
        std.mem.copy(u8, result, output.slice());
        return result;
    } else {
        return null;
    }
}

pub fn dpapi_unwrap(buffer: []u8, allocator: std.mem.Allocator) !?[]u8 {
    var input: Blob = Blob.new(buffer);

    var output: *Blob = try allocator.create(Blob);
    defer output.deinit(allocator);

    var descOut: win.LPWSTR = undefined;

    var success = CryptUnprotectData(&input, &descOut, null, null, null, CRYPTPROTECT_UI_FORBIDDEN, output);
    if (success == 1) {
        const result: []u8 = try allocator.alloc(u8, output.*.cbData);
        std.mem.copy(u8, result, output.slice());
        return result;
    } else {
        return null;
    }
}

fn roundTrip(input: []u8, allocator: std.mem.Allocator) !?[]u8 {
    const encrypted = try dpapi_wrap(input, allocator);
    if (encrypted != null) {
        defer allocator.free(encrypted.?);
        return try dpapi_unwrap(encrypted.?, allocator);
    } else {
        return null;
    }
}

pub fn readStdIn(allocator: std.mem.Allocator) ![]u8 {
    const max_input_size = 1024 * 1024 * 1024;
    return try std.io.getStdIn().reader().readAllAlloc(allocator, max_input_size);
}

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    const input = try readStdIn(allocator);
    defer allocator.free(input);

    // const output = try roundTrip(input, allocator);
    // const output = try dpapi_wrap(input, allocator);
    const output = try dpapi_unwrap(input, allocator);
    if (output != null) {
        defer allocator.free(output.?);
        try std.io.getStdOut().writer().writeAll(output.?);
    }
}
