const std = @import("std");
const b = @import("base64.zig");

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const args = try std.process.argsAlloc(allocator);

    if (args.len < 2) {
        std.debug.print("Usage: {s} encode|decode <data>\n", .{args[0]});
        return;
    }

    if (args.len == 2) {
        const result = b.encode(allocator, args[1]);
        defer allocator.free(result);
        try std.io.getStdOut().writer().print("{s}\n", .{result});
        return;
    }

    if (std.mem.eql(u8, args[1], "-d")) {
        const result = try b.decode(allocator, args[2]);
        defer allocator.free(result);
        try std.io.getStdOut().writer().print("{s}\n", .{result});
        return;
    }

    std.debug.print("Usage: {s} [-d] <data>\n", .{args[0]});
    return;
}
