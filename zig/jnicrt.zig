//! Portable runtime primitives for the JNIC recreation.
//! C ABI exports, no allocator, pure and thread-safe:
//!   - jn_chacha20: RFC 8439 ChaCha20 keystream XOR
//!   - jn_fnv1a64:  FNV-1a 64-bit
//!   - jn_crc32:    IEEE CRC-32 (reflected)

const std = @import("std");

// ---------------------------------------------------------------------------
// ChaCha20 (RFC 8439)
// ---------------------------------------------------------------------------

/// RFC 8439 section 2.1.1: quarter round on state words (a,b,c,d).
fn qr(s: *[16]u32, comptime a: usize, comptime b: usize, comptime c: usize, comptime d: usize) void {
    s[a] +%= s[b];
    s[d] ^= s[a];
    s[d] = std.math.rotl(u32, s[d], 16);
    s[c] +%= s[d];
    s[b] ^= s[c];
    s[b] = std.math.rotl(u32, s[b], 12);
    s[a] +%= s[b];
    s[d] ^= s[a];
    s[d] = std.math.rotl(u32, s[d], 8);
    s[c] +%= s[d];
    s[b] ^= s[c];
    s[b] = std.math.rotl(u32, s[b], 7);
}

/// RFC 8439 section 2.3: one 64-byte keystream block.
/// State layout: constants, key LE words 4..11, counter (word 12), nonce LE words 13..15.
fn block(out: *[64]u8, kw: [8]u32, ctr: u32, nw: [3]u32) void {
    var s: [16]u32 = .{
        0x61707865, 0x3320646E, 0x79622D32, 0x6B206574, // "expa" "nd 3" "2-by" "te k"
        kw[0],     kw[1],     kw[2],     kw[3],
        kw[4],     kw[5],     kw[6],     kw[7],
        ctr,       nw[0],     nw[1],     nw[2],
    };
    const init = s;
    var r: usize = 0;
    while (r < 10) : (r += 1) { // 20 rounds = 10 double rounds (section 2.2)
        qr(&s, 0, 4, 8, 12);
        qr(&s, 1, 5, 9, 13);
        qr(&s, 2, 6, 10, 14);
        qr(&s, 3, 7, 11, 15);
        qr(&s, 0, 5, 10, 15);
        qr(&s, 1, 6, 11, 12);
        qr(&s, 2, 7, 8, 13);
        qr(&s, 3, 4, 9, 14);
    }
    for (&s, 0..) |*w, i| w.* +%= init[i];
    for (0..16) |i| std.mem.writeInt(u32, out[i * 4 ..][0..4], s[i], .little); // LE serialize
}

/// XOR `len` bytes of `in` with the ChaCha20 keystream into `out`.
/// Counter starts at 1 (RFC 8439 AEAD / section 2.5.2 convention), increments per block.
/// Byte-wise XOR: in-place (out == in) and overlapping buffers are safe. len == 0 is a no-op.
pub export fn jn_chacha20(
    out: [*]u8,
    in: [*]const u8,
    len: usize,
    key: *const [32]u8,
    nonce: *const [12]u8,
) callconv(.C) void {
    var kw: [8]u32 = undefined;
    var nw: [3]u32 = undefined;
    for (0..8) |i| kw[i] = std.mem.readInt(u32, key[i * 4 ..][0..4], .little);
    for (0..3) |i| nw[i] = std.mem.readInt(u32, nonce[i * 4 ..][0..4], .little);
    var ctr: u32 = 1;
    var off: usize = 0;
    while (off < len) {
        var ks: [64]u8 = undefined;
        block(&ks, kw, ctr, nw);
        ctr +%= 1; // wraps instead of trapping past 2^32 blocks
        const n = @min(len - off, @as(usize, 64));
        for (ks[0..n], 0..) |k, i| out[off + i] = in[off + i] ^ k;
        off += n;
    }
}

// ---------------------------------------------------------------------------
// FNV-1a 64-bit
// ---------------------------------------------------------------------------

pub export fn jn_fnv1a64(data: [*]const u8, len: usize) callconv(.C) u64 {
    var h: u64 = 0xCBF29CE484222325; // offset basis
    for (data[0..len]) |b| {
        h ^= b;
        h *%= 0x100000001B3; // prime
    }
    return h;
}

// ---------------------------------------------------------------------------
// IEEE CRC-32 (reflected, poly 0xEDB88320)
// ---------------------------------------------------------------------------

const crc_table: [256]u32 = blk: {
    @setEvalBranchQuota(10000);
    var t: [256]u32 = undefined;
    for (&t, 0..) |*e, i| {
        var c: u32 = @intCast(i);
        for (0..8) |_| {
            c = if (c & 1 != 0) 0xEDB88320 ^ (c >> 1) else c >> 1;
        }
        e.* = c;
    }
    break :blk t;
};

pub export fn jn_crc32(data: [*]const u8, len: usize) callconv(.C) u32 {
    var crc: u32 = 0xFFFF_FFFF;
    for (data[0..len]) |b| crc = crc_table[(crc ^ b) & 0xFF] ^ (crc >> 8);
    return crc ^ 0xFFFF_FFFF;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn expectHex(expected_hex: []const u8, actual: []const u8) !void {
    var buf: [512]u8 = undefined;
    if (actual.len * 2 > buf.len) return error.TooBig;
    const digits = "0123456789abcdef";
    for (actual, 0..) |b, i| {
        buf[i * 2] = digits[b >> 4];
        buf[i * 2 + 1] = digits[b & 15];
    }
    try testing.expectEqualStrings(expected_hex, buf[0 .. actual.len * 2]);
}

test "chacha20 keystream matches RFC 8439 section 2.4.2" {
    var key: [32]u8 = undefined;
    for (&key, 0..) |*b, i| b.* = @intCast(i);
    const nonce = [12]u8{ 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00 };
    var out: [64]u8 = [_]u8{0} ** 64; // zero plaintext -> output is the raw keystream
    jn_chacha20(&out, &out, out.len, &key, &nonce);
    // Cross-verified byte-for-byte against JDK 21 JCA "ChaCha20".
    try expectHex(
        "10f1e7e4d13b5915500fdd1fa32071c4" ++
            "c7d1f4c733c068030422aa9ac3d46c4e" ++
            "d2826446079faa0914c2d705d98b02a2",
        out[0..48],
    );
}

test "chacha20 sunscreen vector RFC 8439 section 2.5.2" {
    var key: [32]u8 = undefined;
    for (&key, 0..) |*b, i| b.* = @intCast(i);
    const nonce = [12]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00 };
    const plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    var ct: [plaintext.len]u8 = undefined;
    jn_chacha20(&ct, plaintext, ct.len, &key, &nonce);
    // Cross-verified byte-for-byte against JDK 21 JCA "ChaCha20".
    try expectHex(
        "6e2e359a2568f98041ba0728dd0d6981" ++
            "e97e7aec1d4360c20a27afccfd9fae0b",
        ct[0..32],
    );
    jn_chacha20(&ct, &ct, ct.len, &key, &nonce); // XOR back == decrypt
    try testing.expectEqualSlices(u8, plaintext, &ct);
}

test "chacha20 in-place equals out-of-place" {
    var key: [32]u8 = undefined;
    var nonce: [12]u8 = undefined;
    for (&key, 0..) |*b, i| b.* = @intCast(i * 7 + 3);
    for (&nonce, 0..) |*b, i| b.* = @intCast(i * 11 + 1);
    var src: [200]u8 = undefined;
    for (&src, 0..) |*b, i| b.* = @intCast(i % 251);
    var inplace = src;
    var outplace: [200]u8 = undefined;
    jn_chacha20(&outplace, &src, src.len, &key, &nonce);
    jn_chacha20(&inplace, &inplace, inplace.len, &key, &nonce);
    try testing.expectEqualSlices(u8, &outplace, &inplace);
    jn_chacha20(&inplace, &inplace, inplace.len, &key, &nonce);
    try testing.expectEqualSlices(u8, &src, &inplace);
}

test "chacha20 partial lengths match manual keystream xor" {
    var key: [32]u8 = undefined;
    var nonce: [12]u8 = undefined;
    for (&key, 0..) |*b, i| b.* = @truncate(i *% 131 +% 17);
    for (&nonce, 0..) |*b, i| b.* = @truncate(i *% 29 +% 5);
    for ([_]usize{ 1, 63, 64, 65, 100 }) |len| {
        var ks: [128]u8 = [_]u8{0} ** 128; // encrypting zeros yields the keystream
        jn_chacha20(&ks, &ks, len, &key, &nonce);
        var input: [128]u8 = undefined;
        for (&input, 0..) |*b, i| b.* = @intCast((i * 37 + 11) % 256);
        var got: [128]u8 = undefined;
        jn_chacha20(&got, &input, len, &key, &nonce);
        for (0..len) |i| try testing.expectEqual(input[i] ^ ks[i], got[i]);
    }
}

test "chacha20 len 0 is a no-op" {
    var key: [32]u8 = [_]u8{0} ** 32;
    var nonce: [12]u8 = [_]u8{0} ** 12;
    var one = [1]u8{42};
    jn_chacha20(&one, &one, 0, &key, &nonce);
    try testing.expectEqual(@as(u8, 42), one[0]);
}

test "fnv1a64 known vectors" {
    const empty = [_]u8{};
    try testing.expectEqual(@as(u64, 0xcbf29ce484222325), jn_fnv1a64(&empty, 0));
    try testing.expectEqual(@as(u64, 0xaf63dc4c8601ec8c), jn_fnv1a64("a", 1));
    try testing.expectEqual(@as(u64, 0x85944171f73967e8), jn_fnv1a64("foobar", 6));
}

test "crc32 known vectors" {
    const empty = [_]u8{};
    try testing.expectEqual(@as(u32, 0x00000000), jn_crc32(&empty, 0));
    try testing.expectEqual(@as(u32, 0xCBF43926), jn_crc32("123456789", 9));
}
