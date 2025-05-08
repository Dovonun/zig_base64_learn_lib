const std = @import("std");

const BASE64_GROUP_SIZE = 4;
const RAW_GROUP_SIZE = 3;
const PADDING = '=';

const DecodeError = error{
    InvalidCharacter,
    InvalidInputSize,
};

fn calc_encoded_size(lenght: usize) usize {
    return (std.math.divCeil(usize, lenght, 3) catch {
        unreachable;
    }) * 4; // TODO: read language spec and complain
}

test "calc_encoded_size" {
    try std.testing.expect(calc_encoded_size(1) == 4);
    try std.testing.expect(calc_encoded_size(8) == 12);
    try std.testing.expect(calc_encoded_size(10000) == 13336);
}

fn calc_decoded_size(input: []const u8) usize {
    const threeByte_groups = std.math.divExact(usize, input.len, 4) catch |err| switch (err) {
        error.UnexpectedRemainder => @panic("input length is not valid base64!"),
        error.DivisionByZero => unreachable,
    };

    const prePadSub_bytes = threeByte_groups * 3;
    if (std.mem.endsWith(u8, input, "==")) return prePadSub_bytes - 2;
    if (std.mem.endsWith(u8, input, "=")) return prePadSub_bytes - 1;
    return prePadSub_bytes;
}

test "calc_decoded_size" {
    try std.testing.expect(calc_decoded_size("abc=") == 2);
    try std.testing.expect(calc_decoded_size("AAAAAA==") == 4);
    try std.testing.expect(calc_decoded_size("AAAABBBBCCCC") == 9);
}

pub fn encode_u8(bits: u6) u8 {
    // var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    // const allocator = gpa.allocator();

    std.debug.print("{}\n", .{bits});

    const char: u8 = switch (bits) {
        0...25 => @as(u8, bits) + 'A',
        26...51 => @as(u8, bits) - 26 + 'a',
        52...61 => @as(u8, bits) - 52 + '0',
        62 => "+"[0],
        63 => "/"[0],
    };

    return char;
}

const u6Index_base64_arr = blk: {
    var table: [std.math.maxInt(u6) + 1]u8 = undefined;
    var i: u8 = 0;
    while (i < table.len) : (i += 1) {
        table[i] = switch (i) {
            0...25 => 'A' + i,
            26...51 => 'a' + i - 26,
            52...61 => '0' + i - 52,
            62 => '+',
            63 => '/',
            else => unreachable,
        };
    }
    break :blk table;
};
test "u6Index_base64_table" {
    try std.testing.expect(u6Index_base64_arr[0] == 'A');
    try std.testing.expect(u6Index_base64_arr[1] == 'B');
}

const base64_u6_table = blk: {
    const upper_bound = 'z' + 1;
    var table: [upper_bound]u8 = [_]u8{0x00} ** upper_bound;
    for (u6Index_base64_arr, 0..) |char, i| {
        table[char] = @as(u8, i);
    }
    if (table[PADDING] != 0x00) @panic("Padding char is part of base64 set.");
    table[PADDING] = PADDING;

    break :blk table;
};
test "u8_u6_table" {
    try std.testing.expect(base64_u6_table['A'] == 0);
    try std.testing.expect(base64_u6_table['0'] == 52);
}

pub fn old_encode(allocator: std.mem.Allocator, input: []u8) ![]u8 {
    const foo = allocator.alloc(u8, input.len * 2);

    // const bar: u8 = undefined;
    for (input) |byte| {
        // if (bar < 1) {
        //     foo
        // }
        foo[0] = encode_u8(byte);
    }

    return foo;
}

pub fn encode(allocator: std.mem.Allocator, input: []const u8) []u8 {
    const output = allocator.alloc(u8, calc_encoded_size(input.len)) catch @panic("alloc failed");

    const groups_count = input.len / RAW_GROUP_SIZE;
    const tail_len = input.len - (groups_count * RAW_GROUP_SIZE);
    if (tail_len != 0) {
        std.debug.assert(tail_len == 1 or tail_len == 2);
        const tail = input[input.len - tail_len ..];
        const index = output.len - BASE64_GROUP_SIZE;

        output[index] = u6Index_base64_arr[(tail[0] >> 2)];
        if (tail.len == 2) {
            output[index + 1] = u6Index_base64_arr[((tail[0] & 0x03) << 4) | (tail[1] >> 4)];
            output[index + 2] = u6Index_base64_arr[(tail[1] & 0x0f) << 2];
        } else {
            output[index + 1] = u6Index_base64_arr[((tail[0] & 0x03) << 4)];
            output[index + 2] = PADDING;
        }
        output[index + 3] = PADDING;
    }

    var i: usize = 0;
    while (i < groups_count) : (i += 1) {
        const s_index = i * RAW_GROUP_SIZE;
        const section = input[s_index .. s_index + RAW_GROUP_SIZE];

        const index = i * BASE64_GROUP_SIZE;
        output[index] = u6Index_base64_arr[section[0] >> 2];
        output[index + 1] = u6Index_base64_arr[((section[0] & 0x03) << 4) | (section[1] >> 4)];
        output[index + 2] = u6Index_base64_arr[(section[1] & 0x0f) << 2 | (section[2] >> 6)];
        output[index + 3] = u6Index_base64_arr[section[2] & 0x3f];
    }
    return output;
}
test "encode" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    try std.testing.expectEqualStrings("aGk=", encode(allocator, "hi"));
    try std.testing.expectEqualStrings("YWJj", encode(allocator, "abc"));
    try std.testing.expectEqualStrings("aGVsbG8gd29ybGQ=", encode(allocator, "hello world"));
}

pub fn decode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    const input_buf = allocator.dupe(u8, input) catch @panic("alloc failed");
    for (input_buf) |*c| c.* = base64_u6_table[c.*];

    const vec_len = 16;
    const Vec = @Vector(vec_len, u8); // 128-bit SIMD (16 bytes)
    const zeroes: Vec = @splat(0);

    var v: usize = 0;
    while (v + vec_len <= input_buf.len) : (v += vec_len) {
        const chunk: Vec = input_buf[v..][0..vec_len].*;
        const cmp = chunk == zeroes;
        if (@reduce(.Or, cmp)) return DecodeError.InvalidCharacter;
    }

    while (v < input_buf.len) : (v += 1) {
        std.debug.print("char {x}\n", .{input_buf[v]});
        if (input_buf[v] == 0x00) return DecodeError.InvalidCharacter;
    }

    std.debug.print("Input {s}\n", .{input});
    std.debug.print("Input {x}\n", .{input});
    std.debug.print("Input {s}\n", .{input_buf});
    std.debug.print("Input {x}\n", .{input_buf});

    var group_count = std.math.divExact(usize, input_buf.len, 4) catch |err| switch (err) {
        error.UnexpectedRemainder => return DecodeError.InvalidInputSize,
        error.DivisionByZero => unreachable,
    };
    const pad_size: usize = if (input_buf[input_buf.len - 1] != PADDING) 0 else if (input_buf[input_buf.len - 2] == PADDING) 2 else 1;
    const output_size = group_count * RAW_GROUP_SIZE - pad_size;
    const output = allocator.alloc(u8, output_size) catch @panic("alloc failed");
    if (pad_size > 0) blk: {
        group_count -= 1;
        const tail = input_buf[input_buf.len - BASE64_GROUP_SIZE ..];
        const index = output.len - (RAW_GROUP_SIZE - pad_size);
        output[index] = (tail[0] << 2) | (tail[1] >> 4);
        if (pad_size == 2) break :blk;
        output[index + 1] = (tail[1] << 4) | (tail[2] >> 2);
    }
    var i: usize = 0;
    while (i < group_count) : (i += 1) {
        const s_index = i * BASE64_GROUP_SIZE;
        const section = input_buf[s_index .. s_index + BASE64_GROUP_SIZE];

        const index = i * RAW_GROUP_SIZE;
        output[index] = (section[0] << 2) | (section[1] >> 4);
        output[index + 1] = (section[1] << 4) | (section[2] >> 2);
        output[index + 2] = (section[2] << 6) | section[3];
    }
    return output;
}

test "decode" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    std.debug.print("foo", .{});
    try std.testing.expectEqualStrings("hi", try decode(allocator, "aGk="));
    std.debug.print("foo", .{});
    try std.testing.expectEqualStrings("abc", try decode(allocator, "YWJj"));
    try std.testing.expectEqualStrings("hello world", try decode(allocator, "aGVsbG8gd29ybGQ="));
    try std.testing.expectEqualStrings("fwheufzjdf8jsdfll", try decode(allocator, "ZndoZXVmempkZjhqc2RmbGw="));
    try std.testing.expectError(DecodeError.InvalidCharacter, decode(allocator, "d^%@"));
    try std.testing.expectError(DecodeError.InvalidInputSize, decode(allocator, "abc"));
}
