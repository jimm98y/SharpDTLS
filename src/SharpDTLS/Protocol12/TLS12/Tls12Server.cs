using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace SharpDTLS.Protocol12.TLS12
{
    public class Tls12DataReceivedEventArgs : EventArgs
    {
        public Tls12DataReceivedEventArgs(Tls12ServerConnection connection, byte[] data)
        {
            Connection = connection;
            Data = data;
        }

        public Tls12ServerConnection Connection { get; }
        public byte[] Data { get; }
    }

    /// <summary>
    /// TLS 1.2 server: <see cref="Start"/> listens on TCP, or <see cref="Accept"/> serves any connected stream. Each
    /// connection runs the DTLS 1.0/1.2 server handshake over TLS framing with the shared settings.
    /// Set <see cref="Tls12ServerBase.MinimumVersion"/> to also accept TLS 1.0 or 1.1 clients,
    /// and <see cref="Tls12ServerBase.MaximumVersion"/> to speak only those.
    /// </summary>
    public class Tls12Server : Tls12ServerBase, IDisposable
    {
        private readonly ConcurrentDictionary<Tls12ServerConnection, Stream> _connections = new();
        private TcpListener _listener;

        public Tls12Server()
            : this(Dtls12CryptoUtils.GenerateSelfSignedCertificate())
        {
        }

        public Tls12Server(AsymmetricCipherKeyPair keyPair, X509Certificate certificate)
            : base(keyPair, certificate, TlsVersion.Tls12)
        {
        }

        private Tls12Server((AsymmetricCipherKeyPair keyPair, X509Certificate certificate) credentials)
            : this(credentials.keyPair, credentials.certificate)
        {
        }

        public event EventHandler<Tls12ServerConnection> HandshakeFinished;
        public event EventHandler<Tls12DataReceivedEventArgs> ApplicationDataReceived;
        public event EventHandler<Tls12ServerConnection> ConnectionClosed;

        public IReadOnlyCollection<Tls12ServerConnection> Connections => _connections.Keys.ToList();

        /// <summary>Set by <see cref="SharpDTLS.TlsServer"/> while TLS 1.3 is also offered (RFC 8446 §4.1.3 downgrade sentinel).</summary>
        internal bool SignalTls13Downgrade { get => Settings.SignalTls13Downgrade; set => Settings.SignalTls13Downgrade = value; }

        /// <summary>The address the listener is bound to, once started.</summary>
        public IPEndPoint LocalEndpoint => (IPEndPoint)_listener?.LocalEndpoint;

        /// <summary>Listens on <paramref name="endpoint"/> (port 0 picks a free one) and accepts connections until disposed.</summary>
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
                        Accept(client.GetStream(), client.Client.RemoteEndPoint);
                    }
                }
                catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
                {
                    // stopped
                }
            });
        }

        /// <summary>Serves a TLS connection on an already connected <paramref name="stream"/>.</summary>
        public Tls12ServerConnection Accept(Stream stream, EndPoint remoteEndPoint = null)
        {
            var connection = new Tls12ServerConnection(Settings, remoteEndPoint ?? new IPEndPoint(IPAddress.None, 0),
                record => TlsStreamPump.Write(stream, record), stream: true);
            _connections[connection] = stream;
            connection.HandshakeFinished += (_, _) => HandshakeFinished?.Invoke(this, connection);
            connection.ApplicationDataReceived += (_, data) => ApplicationDataReceived?.Invoke(this, new Tls12DataReceivedEventArgs(connection, data));
            connection.Closed += (_, _) =>
            {
                if (_connections.TryRemove(connection, out var s))
                    s.Dispose();
                ConnectionClosed?.Invoke(this, connection);
            };
            OnConnectionCreated(connection);
            TlsStreamPump.Start(stream, connection);
            return connection;
        }

        public void Dispose()
        {
            _listener?.Stop();
            foreach (var connection in _connections.Keys)
                connection.Close();
        }
    }
}
