using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using SharpDTLS.Protocol12;
using SharpDTLS.Protocol12.TLS12;
using SharpDTLS.Protocol13;
using SharpDTLS.Protocol13.TLS13;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace SharpDTLS
{
    public class TlsDataReceivedEventArgs : EventArgs
    {
        public TlsDataReceivedEventArgs(TlsConnectionBase connection, byte[] data)
        {
            Connection = connection;
            Data = data;
        }

        /// <summary>A <see cref="Tls12ServerConnection"/> (TLS 1.0-1.2) or <see cref="Tls13ServerConnection"/> (TLS 1.3).</summary>
        public TlsConnectionBase Connection { get; }
        public byte[] Data { get; }
    }

    /// <summary>
    /// A TLS server for every version: each connection's ClientHello decides between the TLS 1.3 engine
    /// (<see cref="Tls13"/>) and the TLS 1.0-1.2 engine (<see cref="Tls12"/>), whose settings are configured there (the
    /// shared ones also through this class). A TLS 1.2 handshake carries the RFC 8446 downgrade sentinel while TLS 1.3
    /// is enabled.
    /// </summary>
    public class TlsServer : IDisposable
    {
        private TcpListener _listener;

        public TlsServer()
            : this(Dtls13CryptoUtils.GenerateSelfSignedCertificate())
        {
        }

        public TlsServer(AsymmetricCipherKeyPair keyPair, X509Certificate certificate)
        {
            Tls12 = new Tls12Server(keyPair, certificate);
            Tls13 = new Tls13Server(keyPair, certificate);
            Tls12.HandshakeFinished += (_, c) => HandshakeFinished?.Invoke(this, c);
            Tls13.HandshakeFinished += (_, c) => HandshakeFinished?.Invoke(this, c);
            Tls12.ApplicationDataReceived += (_, e) => ApplicationDataReceived?.Invoke(this, new TlsDataReceivedEventArgs(e.Connection, e.Data));
            Tls13.ApplicationDataReceived += (_, e) => ApplicationDataReceived?.Invoke(this, new TlsDataReceivedEventArgs(e.Connection, e.Data));
            Tls12.ConnectionClosed += (_, c) => ConnectionClosed?.Invoke(this, c);
            Tls13.ConnectionClosed += (_, c) => ConnectionClosed?.Invoke(this, c);
        }

        private TlsServer((AsymmetricCipherKeyPair keyPair, X509Certificate certificate) credentials)
            : this(credentials.keyPair, credentials.certificate)
        {
        }

        /// <summary>The TLS 1.0-1.2 engine and its settings (suites, resumption, PSK/SRP...).</summary>
        public Tls12Server Tls12 { get; }

        /// <summary>The TLS 1.3 engine and its settings (suites, groups, tickets...).</summary>
        public Tls13Server Tls13 { get; }

        /// <summary>The oldest version accepted; TLS 1.2 by default (RFC 8996 deprecates 1.0 and 1.1).</summary>
        public ushort MinimumVersion { get => Tls12.MinimumVersion; set => Tls12.MinimumVersion = value; }

        /// <summary>The newest version offered: TLS 1.3 (the default) or TLS 1.2 to turn TLS 1.3 off.</summary>
        public ushort MaximumVersion { get; set; } = TlsVersion.Tls13;

        // ── Settings shared by both engines ──────────────────────────────────────────────────

        /// <summary>Intermediate CA certificates sent after the server certificate.</summary>
        public IList<X509Certificate> IntermediateCertificates
        {
            get => Tls13.IntermediateCertificates;
            set { Tls12.IntermediateCertificates = value; Tls13.IntermediateCertificates = value; }
        }

        /// <summary>Chooses credentials from the client's server_name; null keeps the default certificate.</summary>
        public Func<string, ServerCredentials> CertificateSelector
        {
            get => Tls13.CertificateSelector;
            set { Tls12.CertificateSelector = value; Tls13.CertificateSelector = value; }
        }

        /// <summary>Application protocols (ALPN) in server preference order.</summary>
        public IList<string> ApplicationProtocols
        {
            get => Tls13.ApplicationProtocols;
            set { Tls12.ApplicationProtocols = value; Tls13.ApplicationProtocols = value; }
        }

        public bool RequireClientCertificate
        {
            get => Tls13.RequireClientCertificate;
            set { Tls12.RequireClientCertificate = value; Tls13.RequireClientCertificate = value; }
        }

        public Func<X509Certificate, IReadOnlyList<byte[]>, bool> ClientCertificateValidator
        {
            get => Tls13.ClientCertificateValidator;
            set { Tls12.ClientCertificateValidator = value; Tls13.ClientCertificateValidator = value; }
        }

        public event EventHandler<TlsConnectionBase> HandshakeFinished;
        public event EventHandler<TlsDataReceivedEventArgs> ApplicationDataReceived;
        public event EventHandler<TlsConnectionBase> ConnectionClosed;

        public IReadOnlyCollection<TlsConnectionBase> Connections
            => Tls12.Connections.Cast<TlsConnectionBase>().Concat(Tls13.Connections).ToList();

        public IPEndPoint LocalEndpoint => (IPEndPoint)_listener?.LocalEndpoint;

        public void Start(IPEndPoint endpoint)
        {
            if (_listener != null)
                throw new InvalidOperationException("The server is already listening.");
            _listener = new TcpListener(endpoint);
            _listener.Start();
            var listener = _listener;
            _ = Task.Run(async () =>
            {
                try
                {
                    while (true)
                    {
                        var client = await listener.AcceptTcpClientAsync().ConfigureAwait(false);
                        client.NoDelay = true;
                        _ = AcceptAsync(client.GetStream(), client.Client.RemoteEndPoint);
                    }
                }
                catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
                {
                    // stopped
                }
            });
        }

        /// <summary>
        /// Reads the ClientHello on <paramref name="stream"/> and serves the connection with the engine for the version
        /// it offers. Null when the stream ends or does not start with a ClientHello.
        /// </summary>
        public async Task<TlsConnectionBase> AcceptAsync(Stream stream, EndPoint remoteEndPoint = null, CancellationToken cancellationToken = default)
        {
            byte[] prefix;
            byte[] clientHello;
            try
            {
                (prefix, clientHello) = await ReadClientHelloAsync(stream, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is IOException or InvalidDataException or ObjectDisposedException)
            {
                stream.Dispose();
                return null;
            }

            bool tls13 = ProtocolVersions.IsAtLeast(MaximumVersion, TlsVersion.Tls13) && OffersVersion(clientHello, TlsVersion.Tls13);
            var replay = new PrefixedStream(prefix, stream);
            if (tls13)
                return Tls13.Accept(replay, remoteEndPoint);
            Tls12.SignalTls13Downgrade = ProtocolVersions.IsAtLeast(MaximumVersion, TlsVersion.Tls13);
            return Tls12.Accept(replay, remoteEndPoint);
        }

        /// <summary>Reads whole records until the first handshake message is complete; returns the bytes read and that message.</summary>
        private static async Task<(byte[] Read, byte[] Message)> ReadClientHelloAsync(Stream stream, CancellationToken cancellationToken)
        {
            var read = new List<byte>();
            var handshake = new List<byte>();
            byte[] header = new byte[5];
            while (true)
            {
                await stream.ReadExactlyAsync(header, cancellationToken).ConfigureAwait(false);
                int length = (header[3] << 8) | header[4];
                if (header[0] != 0x16 || header[1] != 0x03 || length == 0 || length > 16384)
                    throw new InvalidDataException("Not a TLS ClientHello.");
                byte[] fragment = new byte[length];
                await stream.ReadExactlyAsync(fragment, cancellationToken).ConfigureAwait(false);
                read.AddRange(header);
                read.AddRange(fragment);
                handshake.AddRange(fragment);
                if (handshake.Count >= 4)
                {
                    int messageLength = (handshake[1] << 16) | (handshake[2] << 8) | handshake[3];
                    if (handshake[0] != 0x01 || messageLength > HandshakeReassembler.MaxMessageLength)
                        throw new InvalidDataException("Not a TLS ClientHello.");
                    if (handshake.Count >= 4 + messageLength)
                        return (read.ToArray(), handshake.GetRange(0, 4 + messageLength).ToArray());
                }
            }
        }

        /// <summary>
        /// Whether a ClientHello (TLS: 4-byte header + body; DTLS: 12-byte header + body, with a cookie) lists
        /// <paramref name="version"/> in supported_versions.
        /// </summary>
        internal static bool OffersVersion(byte[] clientHello, ushort version, bool datagram = false)
        {
            try
            {
                var r = new TlsReader(clientHello.AsSpan(datagram ? 12 : 4).ToArray());
                r.ReadUInt16();
                r.ReadBytes(32);
                r.ReadOpaque8();
                if (datagram)
                    r.ReadOpaque8();
                r.ReadOpaque16();
                r.ReadOpaque8();
                if (r.Remaining == 0)
                    return false;
                var extensions = new TlsReader(r.ReadOpaque16());
                while (extensions.Remaining > 0)
                {
                    ushort type = extensions.ReadUInt16();
                    byte[] body = extensions.ReadOpaque16();
                    if (type != 0x002b)
                        continue;
                    var versions = new TlsReader(body);
                    var list = new TlsReader(versions.ReadOpaque8());
                    while (list.Remaining >= 2)
                        if (list.ReadUInt16() == version)
                            return true;
                }
            }
            catch (DtlsException)
            {
                // malformed: let the engine report it
            }
            return false;
        }

        public void Dispose()
        {
            _listener?.Stop();
            Tls12.Dispose();
            Tls13.Dispose();
        }
    }
}
