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
 *   -verify <ca.pem>    server: require and verify a client certificate; client: verify the server chain
 *   -host <name>        client: with -verify, also check the server certificate's host name
 *   -sni <name>         client: send server_name
 *   -cid <hex>          negotiate connection IDs, asking the peer to send this CID ("-" for none)
 *   -alpn <p1,p2,...>   offer (client) or accept (server) these ALPN protocols; prints "ALPN:<protocol>"
 *   <cert.pem> / -cert  may hold the certificate followed by its intermediates
 *   -cert <c> -key <k>  client: present a client certificate
 *   -group <name|id>    client: initial key share; server: the only accepted group (x25519 | p256 | IANA number)
 *   -srtp <profiles>    offer/accept DTLS-SRTP, e.g. SRTP_AES128_CM_SHA1_80; prints "SRTP:<hex keying material>"
 *   -export <label> <n> print "EXPORT:<hex>" of n bytes exported with label (empty context)
 *   -psk <hex> -psk_identity <id>   authenticate with an external PSK (TLS 1.3 PSK callbacks)
 *   -psk_only           with -psk: psk_ke, no (EC)DHE
 *   -ocsp               client: request an OCSP staple and verify it (with -verify); a bad staple fails the handshake
 *   -ocsp_resp <der>    server: staple this OCSP response for clients that ask
 *   -rpk                offer and accept raw public keys (RFC 7250) in both directions; a ".der" certificate file
 *                       is our SubjectPublicKeyInfo; prints "CERTTYPE:<server> <client>" after the handshake
 *   -rpk_pin <der>      authenticate the peer by this pinned SubjectPublicKeyInfo
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

static unsigned char pskKey[64];
static unsigned int pskKeyLen;
static const char *pskIdentity;
static const char *pskCipher = "TLS13-AES128-GCM-SHA256";

static unsigned int client_psk_cb(WOLFSSL *ssl, const char *hint, char *identity, unsigned int idMax,
                                  unsigned char *key, unsigned int keyMax, const char **ciphersuite)
{
    (void)ssl; (void)hint;
    if (strlen(pskIdentity) >= idMax || pskKeyLen > keyMax) return 0;
    strcpy(identity, pskIdentity);
    memcpy(key, pskKey, pskKeyLen);
    *ciphersuite = pskCipher;
    return pskKeyLen;
}

static unsigned int server_psk_cb(WOLFSSL *ssl, const char *identity, unsigned char *key, unsigned int keyMax,
                                  const char **ciphersuite)
{
    (void)ssl;
    if (strcmp(identity, pskIdentity) != 0 || pskKeyLen > keyMax) return 0;
    memcpy(key, pskKey, pskKeyLen);
    *ciphersuite = pskCipher;
    return pskKeyLen;
}

static const char *ocspRespFile;

/* Server status callback: staple the response from -ocsp_resp (wolfSSL takes ownership of the buffer). */
static int status_cb(WOLFSSL *ssl, void *arg)
{
    (void)arg;
    FILE *f = fopen(ocspRespFile, "rb");
    if (!f) return 3; /* SSL_TLSEXT_ERR_NOACK */
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *resp = (unsigned char *)XMALLOC(len, NULL, DYNAMIC_TYPE_OPENSSL);
    if (!resp || fread(resp, 1, len, f) != (size_t)len) { fclose(f); return 3; }
    fclose(f);
    wolfSSL_set_tlsext_status_ocsp_resp(ssl, resp, (int)len);
    return 0; /* SSL_TLSEXT_ERR_OK */
}

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
    int hrr = 0, resume = 0, pskOnly = 0, mfl = 0, ocsp = 0, rpk = 0, argi = 3;
    const char *rpkPin = NULL;
    const char *pskHex = NULL, *host = NULL, *sni = NULL, *alpn = NULL, *cidHex = NULL;

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
        else if (!strcmp(argv[argi], "-psk") && argi + 1 < argc) pskHex = argv[++argi];
        else if (!strcmp(argv[argi], "-psk_identity") && argi + 1 < argc) pskIdentity = argv[++argi];
        else if (!strcmp(argv[argi], "-psk_only")) pskOnly = 1;
        else if (!strcmp(argv[argi], "-verify") && argi + 1 < argc) verify = argv[++argi];
        else if (!strcmp(argv[argi], "-host") && argi + 1 < argc) host = argv[++argi];
        else if (!strcmp(argv[argi], "-sni") && argi + 1 < argc) sni = argv[++argi];
        else if (!strcmp(argv[argi], "-alpn") && argi + 1 < argc) alpn = argv[++argi];
        else if (!strcmp(argv[argi], "-cid") && argi + 1 < argc) cidHex = argv[++argi];
        else if (!strcmp(argv[argi], "-cert") && argi + 1 < argc) cert = argv[++argi];
        else if (!strcmp(argv[argi], "-key") && argi + 1 < argc) key = argv[++argi];
        else if (!strcmp(argv[argi], "-group") && argi + 1 < argc) group = argv[++argi];
        else if (!strcmp(argv[argi], "-mfl") && argi + 1 < argc) mfl = atoi(argv[++argi]);
        else if (!strcmp(argv[argi], "-ocsp")) ocsp = 1;
        else if (!strcmp(argv[argi], "-rpk")) rpk = 1;
        else if (!strcmp(argv[argi], "-rpk_pin") && argi + 1 < argc) rpkPin = argv[++argi];
        else if (!strcmp(argv[argi], "-ocsp_resp") && argi + 1 < argc) ocspRespFile = argv[++argi];
        else if (!strcmp(argv[argi], "-srtp") && argi + 1 < argc) srtp = argv[++argi];
        else if (!strcmp(argv[argi], "-export") && argi + 2 < argc) { exportLabel = argv[++argi]; exportLength = atoi(argv[++argi]); }
    }

    wolfSSL_Init();
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(server ? wolfDTLSv1_3_server_method() : wolfDTLSv1_3_client_method());
    if (!ctx) fail("CTX_new", NULL, 0);

    if (cert && strstr(cert, ".der")) {
        if (wolfSSL_CTX_use_certificate_file(ctx, cert, WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS)
            fail("load raw public key", NULL, 0);
    } else if (cert && wolfSSL_CTX_use_certificate_chain_file(ctx, cert) != WOLFSSL_SUCCESS) {
        fail("load cert", NULL, 0);
    }
    if (key && wolfSSL_CTX_use_PrivateKey_file(ctx, key, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS)
        fail("load key", NULL, 0);
    if (cipher && wolfSSL_CTX_set_cipher_list(ctx, cipher) != WOLFSSL_SUCCESS)
        fail("cipher list", NULL, 0);

    if (pskHex) {
        size_t hexLen = strlen(pskHex);
        if (!pskIdentity || hexLen % 2 || hexLen / 2 > sizeof(pskKey)) { fprintf(stderr, "bad -psk\n"); return 2; }
        for (size_t i = 0; i < hexLen / 2; i++) sscanf(pskHex + 2 * i, "%2hhx", &pskKey[i]);
        pskKeyLen = (unsigned int)(hexLen / 2);
        if (cipher) pskCipher = cipher;
        if (server) wolfSSL_CTX_set_psk_server_tls13_callback(ctx, server_psk_cb);
        else wolfSSL_CTX_set_psk_client_tls13_callback(ctx, client_psk_cb);
        if (pskOnly && wolfSSL_CTX_no_dhe_psk(ctx) != 0)
            fail("no_dhe_psk", NULL, 0);
    }

    if (ocsp && wolfSSL_CTX_EnableOCSPStapling(ctx) != WOLFSSL_SUCCESS)
        fail("EnableOCSPStapling", NULL, 0);
    if (ocspRespFile) {
        if (wolfSSL_CTX_EnableOCSPStapling(ctx) != WOLFSSL_SUCCESS)
            fail("EnableOCSPStapling", NULL, 0);
        if (wolfSSL_CTX_set_tlsext_status_cb(ctx, status_cb) != WOLFSSL_SUCCESS)
            fail("set_tlsext_status_cb", NULL, 0);
    }

    if (srtp && wolfSSL_CTX_set_tlsext_use_srtp(ctx, srtp) != 0)
        fail("use_srtp", NULL, 0);

    if (verify) {
        if (wolfSSL_CTX_load_verify_locations(ctx, verify, NULL) != WOLFSSL_SUCCESS)
            fail("load verify", NULL, 0);
        wolfSSL_CTX_set_verify(ctx, server ? WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT : WOLFSSL_VERIFY_PEER, NULL);
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
    if (!server && host && wolfSSL_check_domain_name(ssl, host) != WOLFSSL_SUCCESS)
        fail("check_domain_name", NULL, 0);
    if (!server && sni && wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, sni, (unsigned short)strlen(sni)) != WOLFSSL_SUCCESS)
        fail("UseSNI", NULL, 0);
    if (cidHex) {
        if (wolfSSL_dtls_cid_use(ssl) != WOLFSSL_SUCCESS)
            fail("cid_use", NULL, 0);
        if (strcmp(cidHex, "-") != 0) {
            unsigned char cid[255];
            size_t cidLen = strlen(cidHex) / 2;
            for (size_t i = 0; i < cidLen; i++) sscanf(cidHex + 2 * i, "%2hhx", &cid[i]);
            if (wolfSSL_dtls_cid_set(ssl, cid, (unsigned int)cidLen) != WOLFSSL_SUCCESS)
                fail("cid_set", NULL, 0);
        }
    }
    if (alpn) {
        char alpnList[256];
        snprintf(alpnList, sizeof(alpnList), "%s", alpn);
        if (wolfSSL_UseALPN(ssl, alpnList, (unsigned int)strlen(alpnList), WOLFSSL_ALPN_FAILED_ON_MISMATCH) != WOLFSSL_SUCCESS)
            fail("UseALPN", NULL, 0);
    }
    /* the socket is connect()ed, so wolfSSL must use send/recv rather than sendto (EISCONN on macOS) */
    if (wolfSSL_set_dtls_fd_connected(ssl, fd) != WOLFSSL_SUCCESS)
        fail("set fd", NULL, 0);

    if (rpk) {
        const char types[] = { WOLFSSL_CERT_TYPE_RPK, WOLFSSL_CERT_TYPE_X509 };
        if (wolfSSL_set_server_cert_type(ssl, types, 2) != WOLFSSL_SUCCESS || wolfSSL_set_client_cert_type(ssl, types, 2) != WOLFSSL_SUCCESS)
            fail("set cert types", NULL, 0);
    }
    if (rpkPin) {
        unsigned char spki[1024];
        FILE *f = fopen(rpkPin, "rb");
        size_t len = f ? fread(spki, 1, sizeof(spki), f) : 0;
        if (f) fclose(f);
        if (len == 0 || wolfSSL_set_expected_rpk(ssl, spki, (unsigned int)len) != WOLFSSL_SUCCESS)
            fail("set_expected_rpk", NULL, 0);
        wolfSSL_set_verify(ssl, server ? WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT : WOLFSSL_VERIFY_PEER, NULL);
    }
    if (ocsp && !server && wolfSSL_UseOCSPStapling(ssl, WOLFSSL_CSR_OCSP, 0) != WOLFSSL_SUCCESS)
        fail("UseOCSPStapling", NULL, 0);
    /* max_fragment_length code 1-4 (2^9 to 2^12); the client asks, the server always accepts */
    if (mfl && !server && wolfSSL_UseMaxFragment(ssl, (unsigned char)mfl) != WOLFSSL_SUCCESS)
        fail("UseMaxFragment", NULL, 0);
    /* post-quantum key shares make ClientHellos larger than one datagram */
    if (server && wolfSSL_dtls13_allow_ch_frag(ssl, 1) != WOLFSSL_SUCCESS)
        fail("allow ch frag", NULL, 0);
    if (server && hrr && wolfSSL_send_hrr_cookie(ssl, NULL, 0) != WOLFSSL_SUCCESS)
        fail("hrr cookie", NULL, 0);
    if (group) {
        int g = !strcmp(group, "p256") ? WOLFSSL_ECC_SECP256R1 : !strcmp(group, "x25519") ? WOLFSSL_ECC_X25519 : atoi(group);
        if (server) {
            if (wolfSSL_set_groups(ssl, &g, 1) != WOLFSSL_SUCCESS)
                fail("set groups", NULL, 0);
        } else if (wolfSSL_UseKeyShare(ssl, (word16)g) != WOLFSSL_SUCCESS) {
            fail("key share", NULL, 0);
        }
    }

    ret = server ? wolfSSL_accept(ssl) : wolfSSL_connect(ssl);
    if (ret != WOLFSSL_SUCCESS)
        fail(server ? "accept" : "connect", ssl, ret);

    wolfSSL_dtls_set_using_nonblock(ssl, 1);
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
    if (round > 0)
        printf("%s\n", wolfSSL_session_reused(ssl) ? "RESUMED" : "NOT RESUMED");
    printf("CONNECTED %s\n", wolfSSL_get_cipher_name(ssl));
    if (rpk) {
        int serverType = -1, clientType = -1;
        wolfSSL_get_negotiated_server_cert_type(ssl, &serverType);
        wolfSSL_get_negotiated_client_cert_type(ssl, &clientType);
        printf("CERTTYPE:%d %d\n", serverType, clientType);
    }
    if (alpn) {
        char *protocol = NULL;
        unsigned short protocolLen = 0;
        if (wolfSSL_ALPN_GetProtocol(ssl, &protocol, &protocolLen) == WOLFSSL_SUCCESS)
            printf("ALPN:%.*s\n", protocolLen, protocol);
    }
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
