const std = @import("std");
const b = @import("base64.zig");

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const args = try std.process.argsAlloc(allocator);

    if (args.len != 3) {
        std.debug.print("Usage: {s} encode|decode <data>\n", .{args[0]});
        return;
    }

    const mode = args[1];
    const data = args[2];

    if (std.mem.eql(u8, mode, "encode")) {
        const result = b.encode(allocator, data);
        defer allocator.free(result);
        try std.io.getStdOut().writer().print("{s}\n", .{result});
    } else if (std.mem.eql(u8, mode, "decode")) {
        const result = try b.decode(allocator, data);
        defer allocator.free(result);
        try std.io.getStdOut().writer().print("{s}\n", .{result});
    } else {
        std.debug.print("Unknown mode: {s}\n", .{mode});
    }
}
