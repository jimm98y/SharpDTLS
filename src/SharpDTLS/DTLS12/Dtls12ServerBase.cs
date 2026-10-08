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
    /// and keeps one <see cref="Tls12ServerConnection"/> per remote endpoint, each with its own lock.
    /// </summary>
    public abstract class Dtls12ServerBase : Tls12ServerBase
    {
        private readonly ConcurrentDictionary<string, Tls12ServerConnection> _connections = new();
        private readonly ConcurrentDictionary<string, Tls12ServerConnection> _connectionsById = new();
        private readonly ClientHelloReassembler _clientHelloReassembler = new();

        protected Dtls12ServerBase(IServerTransport serverTransport, AsymmetricCipherKeyPair keyPair, X509Certificate certificate, ushort version)
            : base(keyPair, certificate, version)
        {
            ServerTransport = serverTransport;
            ServerTransport.OnDataReceived += OnDataReceived;
        }

        public IServerTransport ServerTransport { get; }

        /// <summary>Require a valid cookie (HelloVerifyRequest round trip) before allocating state.</summary>
        public bool ShouldSendHelloVerify { get; set; } = true;

        public ushort[] SrtpProtectionProfiles { get => Settings.SrtpProtectionProfiles; set => Settings.SrtpProtectionProfiles = value; }
        public TimeSpan InitialRetransmitTimeout { get => Settings.InitialRetransmitTimeout; set => Settings.InitialRetransmitTimeout = value; }

        /// <summary>
        /// Negotiate connection IDs (RFC 9146) with clients that offer them, routing their records by CID so a client
        /// can change address (see <see cref="Tls12ServerConnection.PeerAddressChanged"/>).
        /// </summary>
        public bool UseConnectionIds { get => Settings.UseConnectionIds; set => Settings.UseConnectionIds = value; }

        /// <summary>Length of the CIDs this server issues.</summary>
        public int ConnectionIdLength { get => Settings.ConnectionIdLength; set => Settings.ConnectionIdLength = value; }

        /// <summary>
        /// Send to a client's new address as soon as an authenticated, newer record arrives from it (the default,
        /// RFC 9146 §6); when false, call ConfirmPeerAddress on the connection after verifying the address.
        /// </summary>
        public bool AutoUpdatePeerAddress { get => Settings.AutoUpdatePeerAddress; set => Settings.AutoUpdatePeerAddress = value; }

        public IReadOnlyCollection<Tls12ServerConnection> Connections => _connections.Values.ToList();

        public Tls12ServerConnection GetConnection(EndPoint endpoint)
            => _connections.TryGetValue(endpoint.ToString(), out var connection) ? connection : null;

        protected Tls12ServerConnection RequireConnection(EndPoint endpoint)
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

        protected virtual void OnConnectionEstablished(Tls12ServerConnection connection) { }
        protected virtual void OnApplicationData(Tls12ServerConnection connection, byte[] data) { }
        protected virtual void OnAlert(Tls12ServerConnection connection, AlertDescription description) { }
        protected virtual void OnConnectionClosed(Tls12ServerConnection connection) { }

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
            Tls12ServerConnection connection = null;
            connection = new Tls12ServerConnection(Settings, endpoint, data => ServerTransport.Send(connection.RemoteEndPoint, data));
            if (!_connections.TryAdd(endpoint.ToString(), connection))
                return;

            connection.HandshakeFinished += (_, _) => OnConnectionEstablished(connection);
            connection.ApplicationDataReceived += (_, data) => OnApplicationData(connection, data);
            connection.AlertReceived += (_, alert) => OnAlert(connection, alert);
            connection.PeerAddressConfirmed += (_, change) =>
            {
                _connections.TryRemove(new KeyValuePair<string, Tls12ServerConnection>(change.Old.ToString(), connection));
                _connections[change.New.ToString()] = connection;
            };
            connection.Closed += (_, _) =>
            {
                _connections.TryRemove(new KeyValuePair<string, Tls12ServerConnection>(connection.RemoteEndPoint.ToString(), connection));
                if (connection.ConnectionId != null)
                    _connectionsById.TryRemove(new KeyValuePair<string, Tls12ServerConnection>(Convert.ToHexString(connection.ConnectionId), connection));
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
