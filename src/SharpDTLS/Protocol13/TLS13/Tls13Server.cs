// SharpDTLS
// Copyright (C) 2026 Lukas Volf
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE 
// SOFTWARE.

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using SharpDTLS.Protocol13.Messages;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace SharpDTLS.Protocol13.TLS13
{
    internal class Tls13DataReceivedEventArgs : EventArgs
    {
        public Tls13DataReceivedEventArgs(Tls13ServerConnection connection, byte[] data)
        {
            Connection = connection;
            Data = data;
        }

        public Tls13ServerConnection Connection { get; }
        public byte[] Data { get; }
    }

    /// <summary>
    /// TLS 1.3 server: <see cref="Start"/> listens on TCP, or <see cref="Accept"/> serves any connected stream. Each
    /// connection runs the DTLS 1.3 server handshake over TLS records with the shared settings; a HelloRetryRequest is
    /// sent only when the client has no key share the server accepts. 0-RTT is accepted under the same rules as for DTLS
    /// once MaxEarlyDataSize is set.
    /// </summary>
    internal class Tls13Server : Tls13ServerBase, IDisposable
    {
        private readonly ConcurrentDictionary<Tls13ServerConnection, Stream> _connections = new();
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

        public event EventHandler<Tls13ServerConnection> HandshakeFinished;
        public event EventHandler<Tls13DataReceivedEventArgs> ApplicationDataReceived;
        public event EventHandler<KeyUpdateDatagram> KeyUpdateReceived;
        public event EventHandler<Tls13ServerConnection> ConnectionClosed;

        /// <summary>0-RTT data accepted before the handshake completes (see MaxEarlyDataSize); it may be a replay.</summary>
        public event EventHandler<Tls13DataReceivedEventArgs> EarlyDataReceived;

        public IReadOnlyCollection<Tls13ServerConnection> Connections => _connections.Keys.ToList();

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
        public Tls13ServerConnection Accept(Stream stream, EndPoint remoteEndPoint = null)
        {
            var connection = new Tls13ServerConnection(this, remoteEndPoint ?? new IPEndPoint(IPAddress.Loopback, 0),
                record => TlsStreamPump.Write(stream, record));
            _connections[connection] = stream;
            OnConnectionCreated(connection);
            TlsStreamPump.Start(stream, connection, ownsStream: true);
            return connection;
        }

        public void Dispose()
        {
            _listener?.Stop();
            foreach (var connection in _connections.Keys)
                connection.Close();
        }

        // ── Callbacks from connections ───────────────────────────────────────────────────────

        internal override void OnConnectionEstablished(Tls13ServerConnection connection) => HandshakeFinished?.Invoke(this, connection);

        internal override void OnApplicationData(Tls13ServerConnection connection, byte[] data)
            => ApplicationDataReceived?.Invoke(this, new Tls13DataReceivedEventArgs(connection, data));

        internal override void OnEarlyData(Tls13ServerConnection connection, byte[] data)
            => EarlyDataReceived?.Invoke(this, new Tls13DataReceivedEventArgs(connection, data));

        internal override void OnKeyUpdate(KeyUpdateDatagram keyUpdate) => KeyUpdateReceived?.Invoke(this, keyUpdate);

        internal override void OnConnectionClosed(Tls13ServerConnection connection)
        {
            if (_connections.TryRemove(connection, out var stream))
                TlsStreamPump.DisposeAfterLinger(stream);
            ConnectionClosed?.Invoke(this, connection);
        }
    }
}
