/*
 * Minimal DTLS 1.3 peer built on wolfSSL, used by the interop tests (wolfSSL's own examples are not
 * shipped by Homebrew). Behaves like `openssl s_server` / `s_client`:
 *
 *   wolfdtls13 server <port> <cert.pem> <key.pem> [options]
 *   wolfdtls13 client <port> [options]
 *
 * options:
 *   -cipher <list>      wolfSSL cipher list, e.g. TLS13-AES128-GCM-SHA256
 *   -hrr                server: send a HelloRetryRequest cookie
 *   -verify <ca.pem>    server: require and verify a client certificate
 *   -cert <c> -key <k>  client: present a client certificate
 *   -group <name>       client: initial key share (x25519 | p256)
 *   -srtp <profiles>    offer/accept DTLS-SRTP, e.g. SRTP_AES128_CM_SHA1_80; prints "SRTP:<hex keying material>"
 *   -export <label> <n> print "EXPORT:<hex>" of n bytes exported with label (empty context)
 *   -resume             two connections: the client resumes the first one's session ticket, the server
 *                       accepts the second connection with the same context; both print "RESUMED" or
 *                       "NOT RESUMED" after the second handshake
 *
 * Prints "ACCEPT" once listening, "CONNECTED <cipher>" after the handshake and "RECV:<data>" for
 * every application record. Each stdin line is sent as application data; the line "KEYUPDATE"
 * triggers a key update instead.
 */
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

static void fail(const char *what, WOLFSSL *ssl, int ret)
{
    char buf[WOLFSSL_MAX_ERROR_SZ];
    int err = ssl ? wolfSSL_get_error(ssl, ret) : ret;
    fprintf(stdout, "ERROR %s: %d %s\n", what, err, wolfSSL_ERR_error_string(err, buf));
    fflush(stdout);
    exit(1);
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: wolfdtls13 server|client <port> ...\n");
        return 2;
    }

    int server = strcmp(argv[1], "server") == 0;
    int port = atoi(argv[2]);
    const char *cert = NULL, *key = NULL, *cipher = NULL, *verify = NULL, *group = NULL, *srtp = NULL, *exportLabel = NULL;
    int exportLength = 0;
    int hrr = 0, resume = 0, argi = 3;

    if (server) {
        if (argc < 5) { fprintf(stderr, "server needs cert and key\n"); return 2; }
        cert = argv[3];
        key = argv[4];
        argi = 5;
    }
    for (; argi < argc; argi++) {
        if (!strcmp(argv[argi], "-cipher") && argi + 1 < argc) cipher = argv[++argi];
        else if (!strcmp(argv[argi], "-hrr")) hrr = 1;
        else if (!strcmp(argv[argi], "-resume")) resume = 1;
        else if (!strcmp(argv[argi], "-verify") && argi + 1 < argc) verify = argv[++argi];
        else if (!strcmp(argv[argi], "-cert") && argi + 1 < argc) cert = argv[++argi];
        else if (!strcmp(argv[argi], "-key") && argi + 1 < argc) key = argv[++argi];
        else if (!strcmp(argv[argi], "-group") && argi + 1 < argc) group = argv[++argi];
        else if (!strcmp(argv[argi], "-srtp") && argi + 1 < argc) srtp = argv[++argi];
        else if (!strcmp(argv[argi], "-export") && argi + 2 < argc) { exportLabel = argv[++argi]; exportLength = atoi(argv[++argi]); }
    }

    wolfSSL_Init();
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(server ? wolfDTLSv1_3_server_method() : wolfDTLSv1_3_client_method());
    if (!ctx) fail("CTX_new", NULL, 0);

    if (cert && wolfSSL_CTX_use_certificate_file(ctx, cert, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS)
        fail("load cert", NULL, 0);
    if (key && wolfSSL_CTX_use_PrivateKey_file(ctx, key, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS)
        fail("load key", NULL, 0);
    if (cipher && wolfSSL_CTX_set_cipher_list(ctx, cipher) != WOLFSSL_SUCCESS)
        fail("cipher list", NULL, 0);

    if (srtp && wolfSSL_CTX_set_tlsext_use_srtp(ctx, srtp) != 0)
        fail("use_srtp", NULL, 0);

    if (verify) {
        if (wolfSSL_CTX_load_verify_locations(ctx, verify, NULL) != WOLFSSL_SUCCESS)
            fail("load verify", NULL, 0);
        wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    } else {
        wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);
    }

    WOLFSSL_SESSION *session = NULL;
    int rounds = resume ? 2 : 1;
    int fd = -1, ret;
    WOLFSSL *ssl = NULL;
    for (int round = 0; round < rounds; round++) {
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    struct sockaddr_in peer;
    socklen_t peerLen = sizeof(peer);

    if (server) {
        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) { perror("bind"); return 1; }
        if (round == 0) {
            printf("ACCEPT\n");
            fflush(stdout);
        }

        char probe[1];
        if (recvfrom(fd, probe, sizeof(probe), MSG_PEEK, (struct sockaddr *)&peer, &peerLen) < 0) { perror("recvfrom"); return 1; }
        if (connect(fd, (struct sockaddr *)&peer, peerLen) != 0) { perror("connect"); return 1; }
    } else {
        peer = addr;
        if (connect(fd, (struct sockaddr *)&peer, sizeof(peer)) != 0) { perror("connect"); return 1; }
    }

    ssl = wolfSSL_new(ctx);
    if (!ssl) fail("new", NULL, 0);
    if (session && wolfSSL_set_session(ssl, session) != WOLFSSL_SUCCESS)
        fail("set session", NULL, 0);
    /* the socket is connect()ed, so wolfSSL must use send/recv rather than sendto (EISCONN on macOS) */
    if (wolfSSL_set_dtls_fd_connected(ssl, fd) != WOLFSSL_SUCCESS)
        fail("set fd", NULL, 0);

    if (server && hrr && wolfSSL_send_hrr_cookie(ssl, NULL, 0) != WOLFSSL_SUCCESS)
        fail("hrr cookie", NULL, 0);
    if (!server && group) {
        int g = !strcmp(group, "p256") ? WOLFSSL_ECC_SECP256R1 : WOLFSSL_ECC_X25519;
        if (wolfSSL_UseKeyShare(ssl, g) != WOLFSSL_SUCCESS)
            fail("key share", NULL, 0);
    }

    ret = server ? wolfSSL_accept(ssl) : wolfSSL_connect(ssl);
    if (ret != WOLFSSL_SUCCESS)
        fail(server ? "accept" : "connect", ssl, ret);

    wolfSSL_dtls_set_using_nonblock(ssl, 1);
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
    if (round > 0)
        printf("%s\n", wolfSSL_session_reused(ssl) ? "RESUMED" : "NOT RESUMED");
    printf("CONNECTED %s\n", wolfSSL_get_cipher_name(ssl));
    fflush(stdout);

    if (round + 1 < rounds) {
        /* First of two connections: let the ticket (client) or the peer's close (server) arrive, then reconnect. */
        char drain[4096];
        for (int i = 0; i < 50; i++) {
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(fd, &rfds);
            struct timeval wait = { 0, 100000 };
            if (select(fd + 1, &rfds, NULL, NULL, &wait) <= 0) {
                wolfSSL_dtls_got_timeout(ssl);
                if (!server && i >= 5) break; /* the ticket follows the handshake closely */
                continue;
            }
            ret = wolfSSL_read(ssl, drain, sizeof(drain));
            if (ret <= 0) {
                int err = wolfSSL_get_error(ssl, ret);
                if (err == WOLFSSL_ERROR_ZERO_RETURN) break;
                if (err != WOLFSSL_ERROR_WANT_READ && err != WOLFSSL_ERROR_WANT_WRITE)
                    fail("read before reconnect", ssl, ret);
            }
        }
        if (!server) {
            session = wolfSSL_get1_session(ssl);
            if (!session) fail("get1_session", NULL, 0);
            wolfSSL_shutdown(ssl);
        }
        wolfSSL_free(ssl);
        close(fd);
        continue;
    }

    if (srtp) {
        unsigned char material[128];
        size_t materialLen = 0;
        /* first call with NULL returns the profile's keying material length */
        wolfSSL_export_dtls_srtp_keying_material(ssl, NULL, &materialLen);
        if (materialLen == 0 || materialLen > sizeof(material) ||
            wolfSSL_export_dtls_srtp_keying_material(ssl, material, &materialLen) != WOLFSSL_SUCCESS)
            fail("export srtp", NULL, 0);
        printf("SRTP:");
        for (size_t i = 0; i < materialLen; i++) printf("%02x", material[i]);
        printf("\n");
    }
    if (exportLabel) {
        unsigned char material[256];
        if (exportLength > (int)sizeof(material) ||
            wolfSSL_export_keying_material(ssl, material, (size_t)exportLength, exportLabel, strlen(exportLabel), NULL, 0, 0) != WOLFSSL_SUCCESS)
            fail("export", NULL, 0);
        printf("EXPORT:");
        for (int i = 0; i < exportLength; i++) printf("%02x", material[i]);
        printf("\n");
    }
    fflush(stdout);
    }

    char buf[4096];
    char line[4096];
    size_t lineLen = 0;
    for (;;) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(STDIN_FILENO, &fds);
        FD_SET(fd, &fds);
        struct timeval tv = { 1, 0 };

        int n = select(fd + 1, &fds, NULL, NULL, &tv);
        if (n < 0) break;
        if (n == 0) {
            wolfSSL_dtls_got_timeout(ssl); /* drive retransmission of unacknowledged messages */
            continue;
        }

        if (FD_ISSET(STDIN_FILENO, &fds)) {
            /* read() rather than stdio: several lines may arrive at once and select() only sees the fd */
            ssize_t got = read(STDIN_FILENO, line + lineLen, sizeof(line) - 1 - lineLen);
            if (got <= 0) break;
            lineLen += (size_t)got;

            char *nl;
            while ((nl = memchr(line, '\n', lineLen)) != NULL) {
                size_t len = (size_t)(nl - line) + 1;
                if (len >= 9 && !strncmp(line, "KEYUPDATE", 9)) {
                    ret = wolfSSL_update_keys(ssl);
                    if (ret != WOLFSSL_SUCCESS && wolfSSL_get_error(ssl, ret) != WOLFSSL_ERROR_WANT_WRITE)
                        fail("update_keys", ssl, ret);
                    printf("KEYUPDATE SENT\n");
                    fflush(stdout);
                } else if (wolfSSL_write(ssl, line, (int)len) <= 0) {
                    fail("write", ssl, -1);
                }
                memmove(line, line + len, lineLen - len);
                lineLen -= len;
            }
        }

        if (FD_ISSET(fd, &fds)) {
            /* drain: a datagram may hold several records, and non-data records (ACK, tickets) return WANT_READ */
            for (;;) {
                ret = wolfSSL_read(ssl, buf, sizeof(buf) - 1);
                if (ret > 0) {
                    buf[ret] = 0;
                    printf("RECV:%s\n", buf);
                    fflush(stdout);
                    if (wolfSSL_pending(ssl) > 0) continue;
                    break;
                }
                int err = wolfSSL_get_error(ssl, ret);
                if (err == WOLFSSL_ERROR_ZERO_RETURN) { printf("CLOSED\n"); fflush(stdout); goto done; }
                if (err != WOLFSSL_ERROR_WANT_READ && err != WOLFSSL_ERROR_WANT_WRITE)
                    fail("read", ssl, ret);
                break;
            }
        }
    }

done:
    if (session) wolfSSL_SESSION_free(session);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    return 0;
}
