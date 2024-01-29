const std = @import("std");
const net = std.net;
const fs = std.fs;
const print = std.debug.print;

const ssl = @cImport({
    @cInclude("openssl/ssl.h");
    @cInclude("openssl/rand.h");
});

pub fn main() !void {
    var server = net.StreamServer.init(.{ .reuse_address = true });
    defer server.deinit();
    try server.listen(net.Address.parseIp("127.0.0.1", 5000) catch unreachable);
    print("listening to {}\n", .{server.listen_address});

    // Self-signed certificate generation

    const ec_key = ssl.EC_KEY_new_by_curve_name(ssl.NID_X9_62_prime256v1);
    x(ssl.EC_KEY_generate_key(ec_key));
    const kp = ssl.EVP_PKEY_new();
    x(ssl.EVP_PKEY_assign_EC_KEY(kp, ec_key));

    const cert = ssl.X509_new();
    x(ssl.X509_set_version(cert, ssl.X509_VERSION_3));
    var serial: u64 = undefined;
    x(ssl.RAND_bytes(@ptrCast([*c]u8, &serial), @sizeOf(@TypeOf(serial))));
    x(ssl.ASN1_INTEGER_set_uint64(ssl.X509_get_serialNumber(cert), serial));
    _ = ssl.X509_gmtime_adj(ssl.X509_get_notBefore(cert), 0);
    _ = ssl.X509_gmtime_adj(ssl.X509_get_notAfter(cert), 86400 * 100);
    const subject = ssl.X509_get_subject_name(cert);
    x(ssl.X509_NAME_add_entry_by_txt(
        subject,
        "C",
        ssl.MBSTRING_ASC,
        "FR",
        "FR".len,
        -1,
        0,
    ));
    x(ssl.X509_NAME_add_entry_by_txt(
        subject,
        "O",
        ssl.MBSTRING_ASC,
        "TLS mobility example",
        "TLS mobility example".len,
        -1,
        0,
    ));
    x(ssl.X509_set_issuer_name(cert, subject));

    const ekus = ssl.sk_ASN1_OBJECT_new_null();
    _ = ssl.sk_ASN1_OBJECT_push(ekus, ssl.OBJ_nid2obj(ssl.NID_server_auth));
    x(ssl.X509_add1_ext_i2d(cert, ssl.NID_ext_key_usage, ekus, 1, 0));

    x(ssl.X509_set_pubkey(cert, kp));
    _ = ssl.X509_sign(cert, kp, ssl.EVP_sha256());

    // Create a TLS context with the self-signed certificate

    const ctx = ssl.SSL_CTX_new(ssl.TLS_method());
    x(ssl.SSL_CTX_use_PrivateKey(ctx, kp));
    x(ssl.SSL_CTX_use_certificate(ctx, cert));
    ssl.SSL_CTX_set_info_callback(ctx, debugCb);

    // Connection handler

    while (true) {
        var conn = try server.accept();
        defer conn.stream.close();
        var client_fd = conn.stream.handle;
        print("Accepting a new client connection\n", .{});

        // Create a new TLS session

        var session = ssl.SSL_new(ctx);
        var bio_session = ssl.BIO_new_socket(client_fd, ssl.BIO_CLOSE);
        ssl.SSL_set_bio(session, bio_session, bio_session);
        x(ssl.SSL_accept(session));

        // Read the client HTTP query

        var read_buf: [4096]u8 = undefined;
        var n = ssl.SSL_read(session, &read_buf, @sizeOf(@TypeOf(read_buf)));
        if (n < 0) {
            print("read error\n", .{});
            continue;
        } else if (n == 0) {
            print("zero read: {}\n", .{ssl.SSL_get_error(session, 0)});
        }

        // Send the response

        const bio = ssl.BIO_new(ssl.BIO_s_mem());
        _ = ssl.BIO_puts(bio, "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n");
        _ = ssl.BIO_puts(bio, "Hello from fst-boringssl with TLS mobility!\r\n");

        var resp_buf: [*c]u8 = undefined;
        var resp_buf_len: usize = undefined;
        _ = ssl.BIO_mem_contents(bio, &resp_buf, &resp_buf_len);
        print("Responding on the migrated session\n", .{});
        _ = ssl.SSL_write(session, resp_buf, @intCast(c_int, resp_buf_len));

        // Serialize the TLS state

        var cbb: ssl.CBB = undefined;
        x(ssl.CBB_init(&cbb, 1024));
        x(ssl.SSL_serialize_entire_state(session, &cbb));
        const cbb_len = ssl.CBB_len(&cbb);
        const cbb_data = ssl.CBB_data(&cbb)[0..cbb_len];
        var fd = try fs.cwd().createFile("/tmp/state.der", .{});
        defer fd.close();
        const stream = fd.writer();
        try stream.writeAll(cbb_data);
    }
}

fn x(v: c_int) void {
    if (v != 1) print("boringSSL error\n", .{});
}

fn debugCb(_: ?*const ssl.SSL, type_: c_int, _: c_int) callconv(.C) void {
    switch (type_) {
        ssl.SSL_CB_HANDSHAKE_START => print("HANDSHAKE START\n", .{}),
        ssl.SSL_CB_HANDSHAKE_DONE => print("HANDSHAKE DONE\n", .{}),
        ssl.SSL_CB_ACCEPT_LOOP => print("ACCEPT LOOP\n", .{}),
        ssl.SSL_CB_ACCEPT_EXIT => print("ACCEPT EXIT\n", .{}),
        ssl.SSL_CB_CONNECT_LOOP => print("CONNECT LOOP\n", .{}),
        ssl.SSL_CB_CONNECT_EXIT => print("CONNECT EXIT\n", .{}),
        ssl.SSL_CB_READ => print("READ\n", .{}),
        ssl.SSL_CB_WRITE => print("WRITE\n", .{}),
        ssl.SSL_CB_ALERT => print("ALERT\n", .{}),
        ssl.SSL_CB_READ_ALERT => print("READ ALERT\n", .{}),
        ssl.SSL_CB_WRITE_ALERT => print("WRITE ALERT\n", .{}),
        else => {},
    }
}
