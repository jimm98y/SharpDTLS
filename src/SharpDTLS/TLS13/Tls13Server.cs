using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using SharpDTLS.DTLS13;
using SharpDTLS.DTLS13.Messages;
using SharpDTLS.TLS12;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace SharpDTLS.TLS13
{
    public class Tls13DataReceivedEventArgs : EventArgs
    {
        public Tls13DataReceivedEventArgs(Dtls13ServerConnection connection, byte[] data)
        {
            Connection = connection;
            Data = data;
        }

        public Dtls13ServerConnection Connection { get; }
        public byte[] Data { get; }
    }

    /// <summary>
    /// TLS 1.3 server: <see cref="Start"/> listens on TCP, or <see cref="Accept"/> serves any connected stream. Each
    /// connection runs the DTLS 1.3 server handshake over TLS records with the shared settings; a HelloRetryRequest is
    /// sent only when the client has no key share the server accepts.
    /// </summary>
    public class Tls13Server : Tls13ServerBase, IDisposable
    {
        private readonly ConcurrentDictionary<Dtls13ServerConnection, Stream> _connections = new();
        private TcpListener _listener;

        public Tls13Server()
            : this(Dtls13CryptoUtils.GenerateSelfSignedCertificate())
        {
        }

        public Tls13Server(AsymmetricCipherKeyPair keyPair, X509Certificate certificate)
            : base(keyPair, certificate)
        {
        }

        private Tls13Server((AsymmetricCipherKeyPair keyPair, X509Certificate certificate) credentials)
            : this(credentials.keyPair, credentials.certificate)
        {
        }

        public event EventHandler<Dtls13ServerConnection> HandshakeFinished;
        public event EventHandler<Tls13DataReceivedEventArgs> ApplicationDataReceived;
        public event EventHandler<KeyUpdateDatagram> KeyUpdateReceived;
        public event EventHandler<Dtls13ServerConnection> ConnectionClosed;

        public IReadOnlyCollection<Dtls13ServerConnection> Connections => _connections.Keys.ToList();

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

        /// <summary>Serves a TLS 1.3 connection on an already connected <paramref name="stream"/>.</summary>
        public Dtls13ServerConnection Accept(Stream stream, EndPoint remoteEndPoint = null)
        {
            var connection = new Dtls13ServerConnection(this, remoteEndPoint ?? new IPEndPoint(IPAddress.Loopback, 0),
                record => TlsStreamPump.Write(stream, record));
            _connections[connection] = stream;
            TlsStreamPump.Start(stream, connection);
            return connection;
        }

        public void Dispose()
        {
            _listener?.Stop();
            foreach (var connection in _connections.Keys)
                connection.Close();
        }

        // ── Callbacks from connections ───────────────────────────────────────────────────────

        internal override void OnConnectionEstablished(Dtls13ServerConnection connection) => HandshakeFinished?.Invoke(this, connection);

        internal override void OnApplicationData(Dtls13ServerConnection connection, byte[] data)
            => ApplicationDataReceived?.Invoke(this, new Tls13DataReceivedEventArgs(connection, data));

        internal override void OnEarlyData(Dtls13ServerConnection connection, byte[] data) { } // 0-RTT is not accepted over TLS

        internal override void OnKeyUpdate(KeyUpdateDatagram keyUpdate) => KeyUpdateReceived?.Invoke(this, keyUpdate);

        internal override void OnConnectionClosed(Dtls13ServerConnection connection)
        {
            if (_connections.TryRemove(connection, out var stream))
                stream.Dispose();
            ConnectionClosed?.Invoke(this, connection);
        }
    }
}
