using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using SharpDTLS.DTLS12;
using SharpDTLS.TLS13;
using SharpSRTP.UDP;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;

namespace SharpDTLS.DTLS13
{
    public class DtlsDataReceivedEventArgs : EventArgs
    {
        public DtlsDataReceivedEventArgs(EndPoint remoteEndPoint, TlsConnectionBase connection, byte[] data)
        {
            RemoteEndPoint = remoteEndPoint;
            Connection = connection;
            Data = data;
        }

        public EndPoint RemoteEndPoint { get; }

        /// <summary>A <see cref="Tls12ServerConnection"/> (DTLS 1.0-1.2) or <see cref="Tls13ServerConnection"/> (DTLS 1.3).</summary>
        public TlsConnectionBase Connection { get; }
        public byte[] Data { get; }
    }

    /// <summary>
    /// A DTLS server for every version on one transport: each client's ClientHello decides between the DTLS 1.3 engine
    /// (<see cref="Dtls13"/>) and the DTLS 1.0-1.2 engine (<see cref="Dtls12"/>), whose settings are configured there
    /// (the shared ones also through this class); its later datagrams go to the same engine. A DTLS 1.2 handshake
    /// carries the RFC 9147 §5.3 downgrade sentinel while DTLS 1.3 is enabled.
    /// </summary>
    public class DtlsServer
    {
        private readonly EnginePort _port12;
        private readonly EnginePort _port13;
        private readonly ClientHelloReassembler _clientHelloReassembler = new();

        public DtlsServer(IServerTransport serverTransport)
            : this(serverTransport, Dtls13CryptoUtils.GenerateSelfSignedCertificate())
        {
        }

        public DtlsServer(IServerTransport serverTransport, AsymmetricCipherKeyPair keyPair, X509Certificate certificate)
        {
            ServerTransport = serverTransport;
            _port12 = new EnginePort(serverTransport);
            _port13 = new EnginePort(serverTransport);
            Dtls12 = new Dtls12Server(_port12, keyPair, certificate);
            Dtls13 = new Dtls13Server(_port13, keyPair, certificate);

            Dtls12.ConnectionEstablished += c => HandshakeFinished?.Invoke(this, c);
            Dtls13.HandshakeFinished += (_, e) => HandshakeFinished?.Invoke(this, ((Dtls13ConnectionEventArgs)e).Connection);
            Dtls12.ConnectionDataReceived += (c, data) => ApplicationDataReceived?.Invoke(this, new DtlsDataReceivedEventArgs(c.RemoteEndPoint, c, data));
            Dtls13.ApplicationDataReceived += (_, e) => ApplicationDataReceived?.Invoke(this, new DtlsDataReceivedEventArgs(e.RemoteEndPoint, e.Connection, e.Data));
            Dtls12.ConnectionEnded += c => ConnectionClosed?.Invoke(this, c);
            Dtls13.ConnectionClosed += (_, e) => ConnectionClosed?.Invoke(this, e.Connection);

            serverTransport.OnDataReceived += OnDataReceived;
        }

        private DtlsServer(IServerTransport serverTransport, (AsymmetricCipherKeyPair keyPair, X509Certificate certificate) credentials)
            : this(serverTransport, credentials.keyPair, credentials.certificate)
        {
        }

        public IServerTransport ServerTransport { get; }

        /// <summary>The DTLS 1.0-1.2 engine and its settings (suites, resumption, PSK/SRP...).</summary>
        public Dtls12Server Dtls12 { get; }

        /// <summary>The DTLS 1.3 engine and its settings (suites, groups, tickets...).</summary>
        public Dtls13Server Dtls13 { get; }

        /// <summary>The oldest version accepted; DTLS 1.2 by default (RFC 8996 deprecates DTLS 1.0).</summary>
        public ushort MinimumVersion { get => Dtls12.MinimumVersion; set => Dtls12.MinimumVersion = value; }

        /// <summary>The newest version offered: DTLS 1.3 (the default) or DTLS 1.2 to turn DTLS 1.3 off.</summary>
        public ushort MaximumVersion { get; set; } = DtlsVersion.Dtls13;

        // ── Settings shared by both engines ──────────────────────────────────────────────────

        /// <summary>Intermediate CA certificates sent after the server certificate.</summary>
        public IList<X509Certificate> IntermediateCertificates
        {
            get => Dtls13.IntermediateCertificates;
            set { Dtls12.IntermediateCertificates = value; Dtls13.IntermediateCertificates = value; }
        }

        /// <summary>Chooses credentials from the client's server_name; null keeps the default certificate.</summary>
        public Func<string, ServerCredentials> CertificateSelector
        {
            get => Dtls13.CertificateSelector;
            set { Dtls12.CertificateSelector = value; Dtls13.CertificateSelector = value; }
        }

        /// <summary>Application protocols (ALPN) in server preference order.</summary>
        public IList<string> ApplicationProtocols
        {
            get => Dtls13.ApplicationProtocols;
            set { Dtls12.ApplicationProtocols = value; Dtls13.ApplicationProtocols = value; }
        }

        /// <summary>SRTP protection profiles in server preference order; null to never negotiate use_srtp.</summary>
        public ushort[] SrtpProtectionProfiles
        {
            get => Dtls13.SrtpProtectionProfiles;
            set { Dtls12.SrtpProtectionProfiles = value; Dtls13.SrtpProtectionProfiles = value; }
        }

        public bool RequireClientCertificate
        {
            get => Dtls13.RequireClientCertificate;
            set { Dtls12.RequireClientCertificate = value; Dtls13.RequireClientCertificate = value; }
        }

        public Func<X509Certificate, IReadOnlyList<byte[]>, bool> ClientCertificateValidator
        {
            get => Dtls13.ClientCertificateValidator;
            set { Dtls12.ClientCertificateValidator = value; Dtls13.ClientCertificateValidator = value; }
        }

        public event EventHandler<TlsConnectionBase> HandshakeFinished;
        public event EventHandler<DtlsDataReceivedEventArgs> ApplicationDataReceived;
        public event EventHandler<TlsConnectionBase> ConnectionClosed;

        public IReadOnlyCollection<TlsConnectionBase> Connections
            => Dtls12.Connections.Cast<TlsConnectionBase>().Concat(Dtls13.Connections).ToList();

        /// <summary>The connection with <paramref name="endpoint"/>: a <see cref="Tls12ServerConnection"/> or a <see cref="Tls13ServerConnection"/>.</summary>
        public TlsConnectionBase GetConnection(EndPoint endpoint)
            => (TlsConnectionBase)Dtls13.GetConnection(endpoint) ?? Dtls12.GetConnection(endpoint);

        public void SendApplicationData(EndPoint endpoint, byte[] data)
            => (GetConnection(endpoint) ?? throw new InvalidOperationException($"No DTLS connection for {endpoint}.")).SendApplicationData(data);

        public void Close(EndPoint endpoint) => GetConnection(endpoint)?.Close();

        // ── Routing ──────────────────────────────────────────────────────────────────────────

        private void OnDataReceived(object sender, byte[] datagram)
        {
            var endpoint = (EndPoint)sender;
            if (datagram.Length == 0)
                return;

            // A known client stays with its engine; CID records (a client that moved) go by their header format.
            if (Dtls13.GetConnection(endpoint) != null || (datagram[0] & 0xE0) == 0x20)
            {
                _port13.Deliver(endpoint, datagram);
                return;
            }
            if (Dtls12.GetConnection(endpoint) != null || datagram[0] == 25)
            {
                _port12.Deliver(endpoint, datagram);
                return;
            }

            try
            {
                foreach (var record in DtlsRecordSplitter.Split(datagram))
                {
                    if (record.Length < 25 || record[0] != 0x16 || record[3] != 0 || record[4] != 0 || record[13] != HandshakeType.ClientHello)
                        continue; // only a ClientHello can start an association

                    // A ClientHello larger than the path MTU arrives fragmented: the engine gets it whole.
                    if (_clientHelloReassembler.TryAdd(endpoint.ToString(), record, out byte[] complete))
                    {
                        bool dtls13 = DtlsVersion.IsAtLeast(MaximumVersion, DtlsVersion.Dtls13)
                                      && TlsServer.OffersVersion(complete.AsSpan(13).ToArray(), DtlsVersion.Dtls13, datagram: true);
                        if (dtls13)
                        {
                            _port13.Deliver(endpoint, complete);
                        }
                        else
                        {
                            Dtls12.SignalTls13Downgrade = DtlsVersion.IsAtLeast(MaximumVersion, DtlsVersion.Dtls13);
                            _port12.Deliver(endpoint, complete);
                        }
                        return;
                    }
                }
            }
            catch (Exception ex)
            {
                // Malformed datagrams from unknown peers are dropped silently.
                Debug.WriteLine($"[DTLS Server] Dropped datagram from {endpoint}: {ex.Message}");
            }
        }

        /// <summary>One engine's view of the transport: the datagrams routed to it, and sending through the real one.</summary>
        private sealed class EnginePort : IServerTransport
        {
            private readonly IServerTransport _transport;

            public EnginePort(IServerTransport transport) => _transport = transport;

            public event EventHandler<byte[]> OnDataReceived;

            public void Send(EndPoint endpoint, byte[] buf) => _transport.Send(endpoint, buf);

            public void Deliver(EndPoint from, byte[] datagram) => OnDataReceived?.Invoke(from, datagram);
        }
    }
}
