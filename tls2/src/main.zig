const std = @import("std");
const net = std.net;
const fs = std.fs;
const print = std.debug.print;

const ssl = @cImport({
    @cInclude("openssl/ssl.h");
    @cInclude("openssl/rand.h");
});

pub fn main() anyerror!void {
    var server = net.StreamServer.init(.{ .reuse_address = true });
    defer server.deinit();
    try server.listen(try net.Address.parseIp("127.0.0.1", 5001));
    print("listening to {}\n", .{server.listen_address});

    const ctx = ssl.SSL_CTX_new(ssl.TLS_method());

    // Connection handler

    while (true) {
        var conn = try server.accept();
        defer conn.stream.close();
        var client_fd = conn.stream.handle;
        print("Accepting a new client connection\n", .{});

        // New session

        var session = ssl.SSL_new(ctx);
        var bio_session = ssl.BIO_new_socket(client_fd, ssl.BIO_CLOSE);
        ssl.SSL_set_bio(session, bio_session, bio_session);

        // Create a new session from a serialized state

        std.debug.print("Wait...\n", .{});
        std.time.sleep(5 * 100_000_000);
        std.debug.print("Done!\n", .{});
        var buf: [4096]u8 = undefined;
        const serialized = try std.fs.cwd().readFile("/tmp/state.der", &buf);

        // Deserialize

        x(ssl.SSL_deserialize_entire_state(session, serialized.ptr, serialized.len));

        // Send the response

        const bio = ssl.BIO_new(ssl.BIO_s_mem());
        _ = ssl.BIO_puts(bio, "Hello from the second server!\r\n");

        var resp_buf: [*c]u8 = undefined;
        var resp_buf_len: usize = undefined;
        _ = ssl.BIO_mem_contents(bio, &resp_buf, &resp_buf_len);
        print("Responding on the migrated session\n", .{});
        _ = ssl.SSL_write(session, resp_buf, @intCast(c_int, resp_buf_len));
    }
}

fn x(v: c_int) void {
    if (v != 1) print("boringSSL error\n", .{});
}
