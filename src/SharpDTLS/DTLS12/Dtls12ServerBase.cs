using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using SharpSRTP.UDP;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;

namespace SharpDTLS.DTLS12
{
    /// <summary>
    /// DTLS 1.0/1.2 server: answers new clients statelessly with HelloVerifyRequest (RFC 6347 §4.2.1)
    /// and keeps one <see cref="Dtls12ServerConnection"/> per remote endpoint, each with its own lock.
    /// </summary>
    public abstract class Dtls12ServerBase
    {
        private readonly ConcurrentDictionary<string, Dtls12ServerConnection> _connections = new();
        private readonly ConcurrentDictionary<string, Dtls12ServerConnection> _connectionsById = new();
        private readonly ClientHelloReassembler _clientHelloReassembler = new();

        protected Dtls12ServerBase(IServerTransport serverTransport, AsymmetricCipherKeyPair keyPair, X509Certificate certificate, ushort version)
        {
            if (certificate != null && keyPair == null)
                throw new ArgumentException("A certificate needs its key pair.");

            Settings = new Dtls12ServerSettings
            {
                KeyPair = keyPair,
                Certificate = certificate,
                MinimumVersion = version,
                MaximumVersion = version,
            };
            ServerTransport = serverTransport;
            ServerTransport.OnDataReceived += OnDataReceived;
        }

        protected Dtls12ServerSettings Settings { get; }

        public IServerTransport ServerTransport { get; }

        /// <summary>Require a valid cookie (HelloVerifyRequest round trip) before allocating state.</summary>
        public bool ShouldSendHelloVerify { get; set; } = true;

        public bool RequireClientCertificate { get => Settings.RequireClientCertificate; set => Settings.RequireClientCertificate = value; }
        public ushort[] SrtpProtectionProfiles { get => Settings.SrtpProtectionProfiles; set => Settings.SrtpProtectionProfiles = value; }
        public TimeSpan InitialRetransmitTimeout { get => Settings.InitialRetransmitTimeout; set => Settings.InitialRetransmitTimeout = value; }
        public Action<string> KeyLogWriter { get => Settings.KeyLogWriter; set => Settings.KeyLogWriter = value; }
        public ushort MinimumVersion { get => Settings.MinimumVersion; set => Settings.MinimumVersion = value; }
        public ushort MaximumVersion { get => Settings.MaximumVersion; set => Settings.MaximumVersion = value; }

        /// <summary>Cipher suites in server preference order; null for all implemented suites.</summary>
        public IList<ushort> CipherSuites { get => Settings.CipherSuites; set => Settings.CipherSuites = value; }

        /// <summary>Intermediate CA certificates sent after the server certificate, issuer of the previous one first.</summary>
        public IList<X509Certificate> IntermediateCertificates { get => Settings.IntermediateCertificates; set => Settings.IntermediateCertificates = value; }

        /// <summary>
        /// Chooses the credentials for the client's server_name (RFC 6066), which is null when the client sent none.
        /// Returning null uses the default certificate.
        /// </summary>
        public Func<string, ServerCredentials> CertificateSelector { get => Settings.CertificateSelector; set => Settings.CertificateSelector = value; }

        /// <summary>
        /// Negotiate connection IDs (RFC 9146) with clients that offer them, routing their records by CID so a client
        /// can change address (see <see cref="Dtls12ServerConnection.PeerAddressChanged"/>).
        /// </summary>
        public bool UseConnectionIds { get => Settings.UseConnectionIds; set => Settings.UseConnectionIds = value; }

        /// <summary>Length of the CIDs this server issues.</summary>
        public int ConnectionIdLength { get => Settings.ConnectionIdLength; set => Settings.ConnectionIdLength = value; }

        /// <summary>
        /// Send to a client's new address as soon as an authenticated, newer record arrives from it (the default,
        /// RFC 9146 §6); when false, call ConfirmPeerAddress on the connection after verifying the address.
        /// </summary>
        public bool AutoUpdatePeerAddress { get => Settings.AutoUpdatePeerAddress; set => Settings.AutoUpdatePeerAddress = value; }

        /// <summary>Application protocols (ALPN, RFC 7301) in server preference order; null to ignore ALPN.</summary>
        public IList<string> ApplicationProtocols { get => Settings.ApplicationProtocols; set => Settings.ApplicationProtocols = value; }

        /// <summary>The most payload per record we accept, advertised with record_size_limit (RFC 8449); null for 16384.</summary>
        public int? RecordSizeLimit { get => Settings.RecordSizeLimit; set => Settings.RecordSizeLimit = value; }

        /// <summary>
        /// Certificate types we authenticate with, in preference order (RFC 7250); null for X.509 only. With
        /// <see cref="CertificateType.RawPublicKey"/> clients that support it get the key pair's SubjectPublicKeyInfo, so a
        /// server can do without a certificate.
        /// </summary>
        public IList<CertificateType> ServerCertificateTypes { get => Settings.ServerCertificateTypes; set => Settings.ServerCertificateTypes = value; }

        /// <summary>Certificate types accepted from clients, in preference order (RFC 7250); null for X.509 only.</summary>
        public IList<CertificateType> ClientCertificateTypes { get => Settings.ClientCertificateTypes; set => Settings.ClientCertificateTypes = value; }

        /// <summary>Checks a client's raw public key (DER SubjectPublicKeyInfo); false aborts with bad_certificate.</summary>
        public Func<byte[], bool> ClientRawPublicKeyValidator { get => Settings.ClientRawPublicKeyValidator; set => Settings.ClientRawPublicKeyValidator = value; }

        /// <summary>A DER OCSP response for the certificate, stapled for clients that ask (RFC 6066 §8); null for none.</summary>
        public byte[] OcspResponse { get => Settings.OcspResponse; set => Settings.OcspResponse = value; }

        public Func<X509Certificate, IReadOnlyList<byte[]>, bool> ClientCertificateValidator
        {
            get => Settings.ClientCertificateValidator;
            set => Settings.ClientCertificateValidator = value;
        }

        /// <summary>Optional psk_identity_hint sent to PSK clients (RFC 4279 §5.2).</summary>
        public byte[] PskIdentityHint { get => Settings.PskIdentityHint; set => Settings.PskIdentityHint = value; }

        /// <summary>Maps a client's PSK identity to its key (null for unknown identities); enables the PSK suites.</summary>
        public Func<byte[], byte[]> PskIdentityResolver { get => Settings.PskIdentityResolver; set => Settings.PskIdentityResolver = value; }

        /// <summary>Maps an SRP username to its verifier (null for unknown users); enables the SRP suites.</summary>
        public Func<byte[], SrpVerifier> SrpVerifierProvider { get => Settings.SrpVerifierProvider; set => Settings.SrpVerifierProvider = value; }

        /// <summary>
        /// Maps a TLS-PWD username to its credential (null for unknown users, whose handshakes are simulated);
        /// enables the ECCPWD suites.
        /// </summary>
        public Func<string, PwdCredential> PwdCredentialProvider { get => Settings.PwdCredentialProvider; set => Settings.PwdCredentialProvider = value; }

        /// <summary>Resumable sessions by session ID; null disables session ID resumption.</summary>
        public IDtls12SessionCache SessionCache { get => Settings.SessionCache; set => Settings.SessionCache = value; }

        /// <summary>
        /// Keys for RFC 5077 session tickets (random per server by default); share them between servers to let them
        /// resume each other's sessions, or set null to disable tickets.
        /// </summary>
        public SessionTicketKeys TicketKeys { get => Settings.TicketKeys; set => Settings.TicketKeys = value; }

        /// <summary>Private key for recovering pwd_protect usernames (RFC 8492 §4.3.2); null accepts only pwd_clear.</summary>
        public Org.BouncyCastle.Crypto.Parameters.ECPrivateKeyParameters PwdProtectionKey { get => Settings.PwdProtectionKey; set => Settings.PwdProtectionKey = value; }

        public IReadOnlyCollection<Dtls12ServerConnection> Connections => _connections.Values.ToList();

        public Dtls12ServerConnection GetConnection(EndPoint endpoint)
            => _connections.TryGetValue(endpoint.ToString(), out var connection) ? connection : null;

        protected Dtls12ServerConnection RequireConnection(EndPoint endpoint)
            => GetConnection(endpoint) ?? throw new InvalidOperationException($"No DTLS connection for {endpoint}.");

        /// <summary>Sends application data to a peer whose handshake has completed.</summary>
        public void SendApplicationData(EndPoint endpoint, byte[] data) => RequireConnection(endpoint).SendApplicationData(data);

        /// <summary>RFC 5705 keying material exporter for an established session.</summary>
        public byte[] ExportKeyingMaterial(EndPoint endpoint, string label, byte[] context, int length)
            => RequireConnection(endpoint).ExportKeyingMaterial(label, context, length);

        /// <summary>SRTP master keys and salts (RFC 5764 §4.2), or null when use_srtp was not negotiated.</summary>
        public DtlsSrtpKeys GetSrtpKeys(EndPoint endpoint) => GetConnection(endpoint)?.GetSrtpKeys();

        public void Close(EndPoint endpoint) => GetConnection(endpoint)?.Close();

        // ── Hooks for the version-specific facades ───────────────────────────────────────────

        protected virtual void OnConnectionEstablished(Dtls12ServerConnection connection) { }
        protected virtual void OnApplicationData(Dtls12ServerConnection connection, byte[] data) { }
        protected virtual void OnAlert(Dtls12ServerConnection connection, AlertDescription description) { }
        protected virtual void OnConnectionClosed(Dtls12ServerConnection connection) { }

        // ── Stateless ClientHello processing ─────────────────────────────────────────────────

        private void OnDataReceived(object sender, byte[] datagram)
        {
            var endpoint = (EndPoint)sender;

            // tls12_cid records name their connection, whatever address they come from (RFC 9146 §3).
            int cidLength = Settings.ConnectionIdLength;
            if (Settings.UseConnectionIds && datagram.Length >= 13 + cidLength && datagram[0] == 25
                && _connectionsById.TryGetValue(Convert.ToHexString(datagram, 11, cidLength), out var byId))
            {
                byId.ProcessDatagram(datagram, endpoint);
                return;
            }

            if (_connections.TryGetValue(endpoint.ToString(), out var connection))
            {
                connection.ProcessDatagram(datagram, endpoint);
                return;
            }

            try
            {
                foreach (var record in DtlsRecordSplitter.Split(datagram))
                {
                    if (record.Length < 25 || record[0] != 0x16 || record[3] != 0 || record[4] != 0 || record[13] != HandshakeType.ClientHello)
                        continue; // only a ClientHello can start an association

                    // A ClientHello larger than the path MTU arrives fragmented.
                    if (_clientHelloReassembler.TryAdd(endpoint.ToString(), record, out byte[] complete))
                    {
                        HandleClientHello(endpoint, complete);
                        return;
                    }
                }
            }
            catch (Exception ex)
            {
                // Malformed datagrams from unknown peers are dropped silently.
                Debug.WriteLine($"[DTLS12 Server] Dropped datagram from {endpoint}: {ex.Message}");
            }
        }

        private void HandleClientHello(EndPoint endpoint, byte[] record)
        {
            ulong recordSeq = 0;
            for (int i = 5; i < 11; i++)
                recordSeq = (recordSeq << 8) | record[i];
            byte[] message = record.AsSpan(13).ToArray();
            int messageSeq = (message[4] << 8) | message[5];
            var clientHello = ClientHelloMessage.Decode(message.AsSpan(12).ToArray());

            var ip = (IPEndPoint)endpoint;
            if (ShouldSendHelloVerify &&
                (clientHello.Cookie.Length == 0 || !Dtls12CryptoUtils.ValidateCookie(DateTime.UtcNow, ip.Address.ToString(), ip.Port, clientHello.Cookie)))
            {
                SendHelloVerifyRequest(endpoint, Dtls12CryptoUtils.CreateCookie(DateTime.UtcNow, ip.Address.ToString(), ip.Port), recordSeq, messageSeq);
                return;
            }

            // Replies go to the connection's current address, which moves with connection IDs.
            Dtls12ServerConnection connection = null;
            connection = new Dtls12ServerConnection(Settings, endpoint, data => ServerTransport.Send(connection.RemoteEndPoint, data));
            if (!_connections.TryAdd(endpoint.ToString(), connection))
                return;

            connection.HandshakeFinished += (_, _) => OnConnectionEstablished(connection);
            connection.ApplicationDataReceived += (_, data) => OnApplicationData(connection, data);
            connection.AlertReceived += (_, alert) => OnAlert(connection, alert);
            connection.PeerAddressConfirmed += (_, change) =>
            {
                _connections.TryRemove(new KeyValuePair<string, Dtls12ServerConnection>(change.Old.ToString(), connection));
                _connections[change.New.ToString()] = connection;
            };
            connection.Closed += (_, _) =>
            {
                _connections.TryRemove(new KeyValuePair<string, Dtls12ServerConnection>(connection.RemoteEndPoint.ToString(), connection));
                if (connection.ConnectionId != null)
                    _connectionsById.TryRemove(new KeyValuePair<string, Dtls12ServerConnection>(Convert.ToHexString(connection.ConnectionId), connection));
                OnConnectionClosed(connection);
            };

            connection.Start(clientHello, message, recordSeq + 1);
            if (connection.ConnectionId != null && !connection.IsClosed)
                _connectionsById[Convert.ToHexString(connection.ConnectionId)] = connection;
        }

        /// <summary>
        /// HelloVerifyRequest: always DTLS 1.0 version (RFC 6347 §4.2.1), reusing the ClientHello's record
        /// sequence number and message_seq so a stateless server never repeats them.
        /// </summary>
        private void SendHelloVerifyRequest(EndPoint endpoint, byte[] cookie, ulong recordSeq, int messageSeq)
        {
            byte[] body = new HelloVerifyRequestMessage { ServerVersion = DtlsVersion.Dtls10, Cookie = cookie }.Encode();
            var w = new TlsWriter()
                .WriteUInt8(0x16).WriteUInt16(DtlsVersion.Dtls10).WriteUInt16(0)
                .WriteUInt16((int)(recordSeq >> 32)).WriteUInt32((uint)recordSeq)
                .WriteUInt16(12 + body.Length)
                .WriteUInt8(HandshakeType.HelloVerifyRequest).WriteUInt24(body.Length).WriteUInt16(messageSeq)
                .WriteUInt24(0).WriteUInt24(body.Length)
                .WriteBytes(body);

            try { ServerTransport.Send(endpoint, w.ToArray()); }
            catch (Exception ex) { Debug.WriteLine($"[DTLS12 Server] Failed to send HelloVerifyRequest to {endpoint}: {ex.Message}"); }
        }
    }
}
