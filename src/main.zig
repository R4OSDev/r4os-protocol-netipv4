const r4os = @import("r4os");

const TYPE_IPV4: u16 = 0x0800;
const ETHERNET_HEADER_SIZE: usize = 14;
const IPV4_HEADER_SIZE: usize = 20;
const MIN_FRAME_SIZE: usize = 60;
const DEFAULT_TTL: u8 = 64;

comptime {
    asm (r4os.r4dev.protocolEntriesAsm("netipv4_init", "netipv4_shutdown", "netipv4_query", "netipv4_dispatch"));
}

export fn netipv4_init(api: *const r4os.r4dev.ProtocolApi) callconv(.c) i32 {
    var ctx = r4os.r4dev.ProtocolContext.init(api);
    ctx.logInfo("NETIPV4.R4P init");
    _ = ctx.registerRole("net.ipv4", .net, 0);
    _ = ctx.setStatus(.active, "IPv4 R4P active");
    return 0;
}

export fn netipv4_shutdown() callconv(.c) i32 {
    return 0;
}

export fn netipv4_query(out: *r4os.abi.ProtocolStatus) callconv(.c) i32 {
    out.* = .{
        .state = @intFromEnum(r4os.abi.ProtocolState.active),
        .flags = 0,
        .last_error = 0,
        .reserved = 0,
        .note = note("IPv4 R4P ready"),
    };
    return 0;
}

export fn netipv4_dispatch(op: u32, in_buffer: *const r4os.abi.ProtocolBuffer, out_buffer: *r4os.abi.ProtocolBuffer) callconv(.c) i32 {
    _ = out_buffer;
    const request = requestFromBuffer(in_buffer) orelse return -2;
    switch (op) {
        r4os.abi.ipv4_op_handle_rx => handleRx(request),
        r4os.abi.ipv4_op_handle_tx => handleTx(request),
        r4os.abi.ipv4_op_build_packet => buildPacket(request),
        else => return -4,
    }
    return request.result;
}

fn handleRx(request: *r4os.abi.Ipv4Op) void {
    inspect(request);
    if (request.result != r4os.abi.ipv4_result_ok) return;
    if (!isAcceptedDest(request.dest_ip, request.local_ip)) request.result = r4os.abi.ipv4_result_destination;
}

fn handleTx(request: *r4os.abi.Ipv4Op) void {
    inspect(request);
}

fn inspect(request: *r4os.abi.Ipv4Op) void {
    request.ethertype = 0;
    request.payload_len = 0;
    if (request.frame_len < ETHERNET_HEADER_SIZE + IPV4_HEADER_SIZE or request.frame_len > request.frame.len) {
        request.result = r4os.abi.ipv4_result_short;
        return;
    }
    const frame = request.frame[0..@intCast(request.frame_len)];
    request.ethertype = readBe16(frame, 12);
    if (request.ethertype != TYPE_IPV4) {
        request.result = r4os.abi.ipv4_result_not_ipv4;
        return;
    }
    const ip = ETHERNET_HEADER_SIZE;
    const version = frame[ip] >> 4;
    const ihl_words = frame[ip] & 0x0F;
    if (version != 4 or ihl_words < 5) {
        request.result = r4os.abi.ipv4_result_version;
        return;
    }
    const ihl = @as(usize, ihl_words) * 4;
    if (frame.len < ETHERNET_HEADER_SIZE + ihl) {
        request.result = r4os.abi.ipv4_result_short;
        return;
    }
    const total_len = readBe16(frame, ip + 2);
    if (total_len < ihl or frame.len < ETHERNET_HEADER_SIZE + @as(usize, total_len)) {
        request.result = r4os.abi.ipv4_result_length;
        return;
    }
    const flags_fragment = readBe16(frame, ip + 6);
    if ((flags_fragment & 0x1FFF) != 0 or (flags_fragment & 0x2000) != 0) {
        request.result = r4os.abi.ipv4_result_fragment;
        return;
    }
    if (checksum(frame[ip .. ip + ihl]) != 0) {
        request.result = r4os.abi.ipv4_result_checksum;
        return;
    }

    request.protocol = frame[ip + 9];
    request.source_ip = readIp(frame, ip + 12);
    request.dest_ip = readIp(frame, ip + 16);
    const payload = frame[ip + ihl .. ip + @as(usize, total_len)];
    request.payload_len = @intCast(payload.len);
    if (payload.len > 0) @memcpy(request.payload[0..payload.len], payload);
    request.result = r4os.abi.ipv4_result_ok;
}

fn buildPacket(request: *r4os.abi.Ipv4Op) void {
    const total_len = IPV4_HEADER_SIZE + @as(usize, @intCast(request.payload_len));
    const frame_len = ETHERNET_HEADER_SIZE + total_len;
    if (request.payload_len > request.payload.len or total_len > 0xFFFF or request.frame.len < frame_len or request.frame.len < MIN_FRAME_SIZE) {
        request.result = r4os.abi.ipv4_result_buffer_small;
        return;
    }
    var i: usize = 0;
    while (i < request.frame.len) : (i += 1) request.frame[i] = 0;
    i = 0;
    while (i < 6) : (i += 1) request.frame[i] = request.dest_mac[i];
    i = 0;
    while (i < 6) : (i += 1) request.frame[6 + i] = request.source_mac[i];
    writeBe16(request.frame[0..], 12, TYPE_IPV4);

    const ip = ETHERNET_HEADER_SIZE;
    request.frame[ip + 0] = 0x45;
    request.frame[ip + 1] = 0;
    writeBe16(request.frame[0..], ip + 2, @intCast(total_len));
    writeBe16(request.frame[0..], ip + 4, 1);
    writeBe16(request.frame[0..], ip + 6, 0x4000);
    request.frame[ip + 8] = if (request.ttl == 0) DEFAULT_TTL else request.ttl;
    request.frame[ip + 9] = request.protocol;
    writeBe16(request.frame[0..], ip + 10, 0);
    copyIp(request.frame[ip + 12 .. ip + 16], request.source_ip);
    copyIp(request.frame[ip + 16 .. ip + 20], request.dest_ip);
    writeBe16(request.frame[0..], ip + 10, checksum(request.frame[ip .. ip + IPV4_HEADER_SIZE]));

    i = 0;
    const payload_len: usize = @intCast(request.payload_len);
    while (i < payload_len) : (i += 1) request.frame[ip + IPV4_HEADER_SIZE + i] = request.payload[i];
    request.frame_len = if (frame_len < MIN_FRAME_SIZE) MIN_FRAME_SIZE else @intCast(frame_len);
    request.ethertype = TYPE_IPV4;
    request.result = r4os.abi.ipv4_result_ok;
}

fn requestFromBuffer(buffer: *const r4os.abi.ProtocolBuffer) ?*r4os.abi.Ipv4Op {
    if (buffer.data == null) return null;
    if (buffer.len < @sizeOf(r4os.abi.Ipv4Op)) return null;
    return @ptrCast(@alignCast(buffer.data.?));
}

fn checksum(data: []const u8) u16 {
    var sum: u32 = 0;
    var i: usize = 0;
    while (i + 1 < data.len) : (i += 2) {
        sum += (@as(u32, data[i]) << 8) | data[i + 1];
    }
    if (i < data.len) sum += @as(u32, data[i]) << 8;
    while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
    return @intCast(~sum & 0xFFFF);
}

fn sameIp(a: [4]u8, b: [4]u8) bool {
    var i: usize = 0;
    while (i < 4) : (i += 1) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

fn isAcceptedDest(dest_ip: [4]u8, local_ip: [4]u8) bool {
    return sameIp(dest_ip, local_ip) or isBroadcastIp(dest_ip) or isZeroIp(local_ip);
}

fn isBroadcastIp(ip: [4]u8) bool {
    return ip[0] == 255 and ip[1] == 255 and ip[2] == 255 and ip[3] == 255;
}

fn isZeroIp(ip: [4]u8) bool {
    return ip[0] == 0 and ip[1] == 0 and ip[2] == 0 and ip[3] == 0;
}

fn readBe16(buf: []const u8, offset: usize) u16 {
    return (@as(u16, buf[offset]) << 8) | buf[offset + 1];
}

fn writeBe16(buf: []u8, offset: usize, value: u16) void {
    buf[offset] = @intCast(value >> 8);
    buf[offset + 1] = @intCast(value & 0xFF);
}

fn readIp(buf: []const u8, offset: usize) [4]u8 {
    return .{ buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3] };
}

fn copyIp(dst: []u8, src: [4]u8) void {
    var i: usize = 0;
    while (i < 4) : (i += 1) dst[i] = src[i];
}

fn note(comptime text: []const u8) [64]u8 {
    var out: [64]u8 = .{0} ** 64;
    @memcpy(out[0..text.len], text);
    return out;
}
