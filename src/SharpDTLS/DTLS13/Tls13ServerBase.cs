using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using SharpDTLS.DTLS13.Messages;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;

namespace SharpDTLS.DTLS13
{
    /// <summary>
    /// The configuration shared by (D)TLS 1.3 servers: credentials, suites, groups, client authentication, extensions,
    /// resumption and 0-RTT. <see cref="Dtls13Server"/> adds the datagram transport, cookies, SRTP and connection IDs.
    /// </summary>
    public abstract class Tls13ServerBase
    {
        protected Tls13ServerBase(AsymmetricCipherKeyPair keyPair, X509Certificate certificate)
        {
            if (certificate != null && keyPair == null)
                throw new ArgumentException("A certificate needs its key pair.");
            ServerKeyPair = keyPair;
            ServerCertificate = certificate;
        }

        internal AsymmetricCipherKeyPair ServerKeyPair { get; }

        internal X509Certificate ServerCertificate { get; }

        /// <summary>Request a client certificate and abort with certificate_required if none is sent.</summary>
        public bool RequireClientCertificate { get; set; } = false;

        /// <summary>Cipher suites in server preference order: the defaults in <see cref="Dtls13CipherSuite.Supported"/>, or any of <see cref="Dtls13CipherSuite.All"/>.</summary>
        public IList<ushort> CipherSuites { get; set; } = new List<ushort>(Dtls13CipherSuite.Supported);

        /// <summary>Intermediate CA certificates sent after the server certificate, issuer of the previous one first.</summary>
        public IList<X509Certificate> IntermediateCertificates { get; set; }

        /// <summary>
        /// Chooses the credentials for the client's server_name (RFC 6066), which is null when the client sent none.
        /// Returning null uses the default certificate.
        /// </summary>
        public Func<string, ServerCredentials> CertificateSelector { get; set; }

        /// <summary>Application protocols (ALPN, RFC 7301) in server preference order; null to ignore ALPN.</summary>
        public IList<string> ApplicationProtocols { get; set; }

        /// <summary>
        /// The most payload per record we accept (64 to 16384), sent in record_size_limit (RFC 8449) to clients that
        /// offer it; null for 16384. Clients' limits (and max_fragment_length requests) are always honoured.
        /// </summary>
        public int? RecordSizeLimit { get; set; }

        /// <summary>
        /// A DER OCSP response for the server certificate to staple for clients that ask (RFC 8446 §4.4.2.1); null for
        /// none. Certificates from the CertificateSelector staple their own <see cref="ServerCredentials.OcspResponse"/>.
        /// </summary>
        public byte[] OcspResponse { get; set; }

        /// <summary>
        /// Key exchange groups in server preference order (see <see cref="Dtls13Groups"/>). A group the client already
        /// sent a share for is preferred, to avoid a HelloRetryRequest; otherwise the server asks for its best group.
        /// </summary>
        public IList<ushort> SupportedGroups { get; set; } = new List<ushort>(Dtls13Groups.DefaultPreference);

        /// <summary>Optional client certificate validation. Return false to abort with bad_certificate.</summary>
        public Func<X509Certificate, IReadOnlyList<byte[]>, bool> ClientCertificateValidator { get; set; }

        /// <summary>
        /// Certificate types we authenticate with, in preference order (RFC 7250); null for X.509 only. With
        /// <see cref="CertificateType.RawPublicKey"/> clients that support it get the key pair's SubjectPublicKeyInfo, so a
        /// server can do without a certificate.
        /// </summary>
        public IList<CertificateType> ServerCertificateTypes { get; set; }

        /// <summary>Certificate types accepted from clients, in preference order (RFC 7250); null for X.509 only.</summary>
        public IList<CertificateType> ClientCertificateTypes { get; set; }

        /// <summary>
        /// Certificate compression algorithms (RFC 8879) in server preference order: our Certificate is compressed with the
        /// first one the client offers, and clients may compress theirs with any of them. Null disables compression.
        /// </summary>
        public IList<ushort> CertificateCompressionAlgorithms { get; set; } = CertificateCompression.Supported.ToList();

        /// <summary>Checks a client's raw public key (DER SubjectPublicKeyInfo); false aborts with bad_certificate.</summary>
        public Func<byte[], bool> ClientRawPublicKeyValidator { get; set; }

        /// <summary>
        /// Chooses credentials from what the client said (server name, trusted CAs, signature schemes); returning null
        /// falls back to <see cref="CertificateSelector"/> and then the default certificate.
        /// </summary>
        public Func<CertificateSelectionContext, ServerCredentials> CredentialsSelector { get; set; }

        /// <summary>CAs named in our CertificateRequests (certificate_authorities), to guide the client's choice; null names none.</summary>
        public IList<X509Certificate> ClientCertificateAuthorities { get; set; }

        /// <summary>Optional NSS key log sink (SSLKEYLOGFILE format).</summary>
        public Action<string> KeyLogWriter { get; set; }

        /// <summary>
        /// Keys for session tickets (random per server by default): after each full or resumed handshake a client
        /// that offers psk_dhe_ke gets a ticket it can resume with. Null disables tickets and resumption.
        /// </summary>
        public SessionTicketKeys TicketKeys { get; set; } = new SessionTicketKeys();

        /// <summary>Maps a client's PSK identity to its external PSK (null for unknown identities); enables external PSKs.</summary>
        public Func<byte[], Dtls13ExternalPsk> ExternalPskResolver { get; set; }

        /// <summary>
        /// Accept psk_ke, PSK handshakes without (EC)DHE (RFC 8446 §4.2.9), when the client offers it. Off by default:
        /// such handshakes have no forward secrecy. psk_dhe_ke is preferred when the client offers both.
        /// </summary>
        public bool AllowPskOnlyKeyExchange { get; set; }

        /// <summary>
        /// Maximum 0-RTT data per connection advertised in tickets (RFC 8446 §4.2.10); 0 (the default) disables early
        /// data. Early data can be replayed by an attacker, so only enable it for idempotent requests. It is accepted
        /// only without a HelloRetryRequest (set <see cref="ShouldSendHelloRetry"/> to false), for a fresh ticket
        /// (<see cref="EarlyDataFreshnessWindow"/>) whose ClientHello has not been seen before.
        /// </summary>
        public uint MaxEarlyDataSize { get; set; }

        /// <summary>
        /// Anti-replay window (RFC 8446 §8.2): early data is accepted only when the client's ticket age is within this
        /// of the server's view, and each ClientHello is remembered for this long.
        /// </summary>
        public TimeSpan EarlyDataFreshnessWindow { get; set; } = TimeSpan.FromSeconds(10);

        private readonly ConcurrentDictionary<string, DateTime> _seenEarlyDataClientHellos = new();

        /// <summary>
        /// RFC 8446 §8.2 ClientHello recording: remembers the binder of each 0-RTT ClientHello for the freshness
        /// window and refuses a second one. Older entries are outside the window and are pruned.
        /// </summary>
        internal bool RecordEarlyDataClientHello(byte[] binder)
        {
            var now = DateTime.UtcNow;
            foreach (var entry in _seenEarlyDataClientHellos)
                if (now - entry.Value > EarlyDataFreshnessWindow)
                    _seenEarlyDataClientHellos.TryRemove(entry);
            return _seenEarlyDataClientHellos.TryAdd(Convert.ToHexString(binder), now);
        }

        // ── ClientHello decision (shared by the stateless DTLS server and TLS connections) ───────

        /// <summary>
        /// What to do with a ClientHello: send a HelloRetryRequest (with a cookie that binds the suite, ClientHello1 and the
        /// requested group to the peer's address), or start the handshake with a suite, a key share group and, after a
        /// HelloRetryRequest, its state.
        /// </summary>
        internal sealed class ClientHelloDecision
        {
            public HelloRetryRequest HelloRetryRequest { get; init; }
            public ushort SuiteId { get; init; }
            public ushort ShareGroup { get; init; }
            public HelloRetryState Retry { get; init; }
        }

        internal ClientHelloDecision DecideClientHello(ClientHelloDatagram clientHello, byte[] record, System.Net.EndPoint endpoint, bool alwaysRetry)
        {
            bool datagram = clientHello.Datagram;
            var versions = clientHello.Extensions.OfType<ClientSupportedVersions>().FirstOrDefault();
            ushort version = datagram ? ClientSupportedVersions.Dtls13 : ClientSupportedVersions.Tls13;
            if (versions == null || !versions.Versions.Contains(version))
                throw new DtlsException(AlertDescription.ProtocolVersion, datagram ? "Client does not support DTLS 1.3." : "Client does not support TLS 1.3.");
            if (clientHello.LegacyCookie.Length != 0)
                throw new DtlsException(AlertDescription.IllegalParameter, "DTLS 1.3 ClientHello has a legacy_cookie.");

            // A psk_ke-only client sends no key share or groups; whether its PSK is acceptable is checked later.
            var modes = clientHello.Extensions.OfType<PskKeyExchangeModesExtension>().FirstOrDefault();
            bool pskOnly = AllowPskOnlyKeyExchange && clientHello.Extensions.OfType<ClientPreSharedKeyExtension>().Any()
                           && modes != null && modes.Modes.Contains(PskKeyExchangeModesExtension.PskKe)
                           && !modes.Modes.Contains(PskKeyExchangeModesExtension.PskDheKe);
            // Group: the server's most preferred one the client sent a share for, else its most preferred mutual
            // group, requested with a HelloRetryRequest (RFC 8446 §4.2.8).
            var offeredGroups = clientHello.Extensions.OfType<SupportedGroups>().FirstOrDefault()?.Groups ?? Array.Empty<ushort>();
            var shares = clientHello.Extensions.OfType<ClientKeyShareExtension>().FirstOrDefault();
            var mutual = SupportedGroups.Where(g => offeredGroups.Contains(g) && Dtls13Groups.IsSupported(g)).ToList();
            ushort shareGroup = mutual.FirstOrDefault(g => shares?.GetKeyShare(g) != null);
            if (!pskOnly && mutual.Count == 0)
                throw new DtlsException(AlertDescription.HandshakeFailure, "No supported key exchange group in common.");

            ushort suiteId = CipherSuites.FirstOrDefault(s => clientHello.CipherSuites.Contains(s));
            if (suiteId == 0)
                throw new DtlsException(AlertDescription.HandshakeFailure, "No cipher suite in common.");

            bool hasKeyShare = shareGroup != 0;
            var ipEndpoint = (System.Net.IPEndPoint)endpoint;
            string ip = ipEndpoint.Address.ToString();

            var cookie = clientHello.Extensions.OfType<CookieExtension>().FirstOrDefault();
            if (cookie != null && Dtls13CryptoUtils.ValidateCookie(DateTime.UtcNow, ip, ipEndpoint.Port, cookie.Cookie,
                    out ushort cookieSuite, out byte[] clientHello1Hash, out ushort requestedGroup))
            {
                if (!clientHello.CipherSuites.Contains(cookieSuite) || !CipherSuites.Contains(cookieSuite))
                    throw new DtlsException(AlertDescription.IllegalParameter, "ClientHello2 does not offer the cipher suite selected in HelloRetryRequest.");
                // ClientHello2 must carry a share for the group the HelloRetryRequest asked for (RFC 8446 §4.1.2).
                if (requestedGroup != 0)
                {
                    if (shares?.GetKeyShare(requestedGroup) == null)
                        throw new DtlsException(AlertDescription.IllegalParameter, $"ClientHello2 has no {Dtls13Groups.Name(requestedGroup)} key share.");
                    shareGroup = requestedGroup;
                }
                else if (!hasKeyShare && !pskOnly)
                {
                    throw new DtlsException(AlertDescription.IllegalParameter, "ClientHello2 has no usable key share.");
                }
                return new ClientHelloDecision { SuiteId = cookieSuite, ShareGroup = shareGroup, Retry = new HelloRetryState(clientHello1Hash, cookie.Cookie, requestedGroup) };
            }

            if (alwaysRetry || (!hasKeyShare && !pskOnly))
            {
                ushort retryGroup = !hasKeyShare && !pskOnly ? mutual[0] : (ushort)0;
                var transcript = new Dtls13Transcript();
                transcript.AddPlaintextRecord(record);
                byte[] newCookie = Dtls13CryptoUtils.CreateCookie(DateTime.UtcNow, ip, ipEndpoint.Port, suiteId,
                    transcript.Hash(Dtls13CipherSuite.Get(suiteId)), retryGroup);
                // RFC 9147 §5: DTLS servers never echo legacy_session_id; TLS servers always do (RFC 8446 §4.1.3).
                var hrr = new HelloRetryRequest(suiteId, newCookie, retryGroup != 0 ? retryGroup : null,
                    datagram ? Array.Empty<byte>() : clientHello.LegacySessionId, datagram);
                return new ClientHelloDecision { HelloRetryRequest = hrr, SuiteId = suiteId };
            }

            return new ClientHelloDecision { SuiteId = suiteId, ShareGroup = shareGroup };
        }

        internal sealed class HelloRetryState
        {
            public HelloRetryState(byte[] clientHello1Hash, byte[] cookie, ushort requestedGroup)
            {
                ClientHello1Hash = clientHello1Hash;
                Cookie = cookie;
                RequestedGroup = requestedGroup;
            }

            public byte[] ClientHello1Hash { get; }
            public byte[] Cookie { get; }
            public ushort RequestedGroup { get; }
        }

        // ── Callbacks from connections ───────────────────────────────────────────────────────

        internal abstract void OnConnectionEstablished(Dtls13ServerConnection connection);
        internal abstract void OnApplicationData(Dtls13ServerConnection connection, byte[] data);
        internal abstract void OnEarlyData(Dtls13ServerConnection connection, byte[] data);
        internal abstract void OnKeyUpdate(KeyUpdateDatagram keyUpdate);
        internal abstract void OnConnectionClosed(Dtls13ServerConnection connection);
    }
}
