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
using SharpDTLS.Protocol12;
using SharpDTLS.Protocol12.TLS12;
using SharpDTLS.Protocol13;
using SharpDTLS.Protocol13.TLS13;
using System;
using System.Diagnostics;
using System.Collections.Concurrent;
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
    /// A TLS server for every version: each connection's ClientHello decides between TLS 1.3 and TLS 1.0-1.2. A TLS 1.2
    /// handshake carries the RFC 8446 downgrade sentinel while TLS 1.3 is enabled.
    /// </summary>
    public class TlsServer : TlsServerBase, IDisposable
    {
        private TcpListener _listener;
        private int _pendingHandshakes;
        private readonly ConcurrentDictionary<TlsConnectionBase, TaskCompletionSource<bool>> _handshakes = new();

        public TlsServer()
            : this(Dtls13CryptoUtils.GenerateSelfSignedCertificate())
        {
        }

        public TlsServer(AsymmetricCipherKeyPair keyPair, X509Certificate certificate)
            : base(new Tls12Server(keyPair, certificate), new Tls13Server(keyPair, certificate))
        {
            Tls12.HandshakeFinished += (_, c) => OnHandshakeFinished(c);
            Tls13.HandshakeFinished += (_, c) => OnHandshakeFinished(c);
            Tls12.ApplicationDataReceived += (_, e) => ApplicationDataReceived?.Invoke(this, new TlsDataReceivedEventArgs(e.Connection, e.Data));
            Tls13.ApplicationDataReceived += (_, e) => ApplicationDataReceived?.Invoke(this, new TlsDataReceivedEventArgs(e.Connection, e.Data));
            Tls12.ConnectionClosed += (_, c) => ConnectionClosed?.Invoke(this, c);
            Tls13.ConnectionClosed += (_, c) => ConnectionClosed?.Invoke(this, c);
            Tls13.EarlyDataReceived += (_, e) => EarlyDataReceived?.Invoke(this, new TlsDataReceivedEventArgs(e.Connection, e.Data));
            Tls12.ConnectionCreated += OnConnectionCreated;
            Tls13.ConnectionCreated += OnConnectionCreated;
        }

        private TlsServer((AsymmetricCipherKeyPair keyPair, X509Certificate certificate) credentials)
            : this(credentials.keyPair, credentials.certificate)
        {
        }

        /// <summary>The TLS 1.0-1.2 engine.</summary>
        internal Tls12Server Tls12 => (Tls12Server)Engine12;

        /// <summary>The TLS 1.3 engine.</summary>
        internal Tls13Server Tls13 => (Tls13Server)Engine13;

        /// <summary>The oldest version accepted; TLS 1.2 by default (RFC 8996 deprecates 1.0 and 1.1).</summary>
        public ushort MinimumVersion { get => Tls12.MinimumVersion; set => Tls12.MinimumVersion = value; }

        /// <summary>
        /// How long a client accepted by <see cref="Start"/> has to complete its handshake, from its connection on; it
        /// is closed past it. 30 s by default.
        /// </summary>
        public TimeSpan HandshakeTimeout { get; set; } = TimeSpan.FromSeconds(30);

        /// <summary>
        /// The most clients accepted by <see cref="Start"/> that may be in their handshake at once; a new connection
        /// past it is closed. 1,000 by default; 0 for no limit.
        /// </summary>
        public int MaxPendingHandshakes { get; set; } = 1000;

        /// <summary>The newest version offered: TLS 1.3 (the default) or TLS 1.2 to turn TLS 1.3 off.</summary>
        public ushort MaximumVersion { get; set; } = TlsVersion.Tls13;

        public event EventHandler<TlsConnectionBase> HandshakeFinished;
        public event EventHandler<TlsDataReceivedEventArgs> ApplicationDataReceived;

        /// <summary>0-RTT data a TLS 1.3 client sent with its ClientHello (see <see cref="TlsServerBase.MaxEarlyDataSize"/>).</summary>
        public event EventHandler<TlsDataReceivedEventArgs> EarlyDataReceived;

        public event EventHandler<TlsConnectionBase> ConnectionClosed;
        public event EventHandler<TlsAlertEventArgs> AlertReceived;

        /// <summary>A connection was created for a new client, before its handshake runs (e.g. to watch it fail).</summary>
        public event EventHandler<TlsConnectionBase> ConnectionCreated;

        private void OnConnectionCreated(TlsConnectionBase connection)
        {
            connection.AlertReceived += (_, alert) => AlertReceived?.Invoke(this, new TlsAlertEventArgs(connection, alert));
            ConnectionCreated?.Invoke(this, connection);
        }

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
                        if (MaxPendingHandshakes > 0 && Volatile.Read(ref _pendingHandshakes) >= MaxPendingHandshakes)
                        {
                            client.Dispose();
                            continue;
                        }
                        client.NoDelay = true;
                        Interlocked.Increment(ref _pendingHandshakes);
                        _ = ServeAsync(client);
                    }
                }
                catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
                {
                    // stopped
                }
            });
        }

        private void OnHandshakeFinished(TlsConnectionBase connection)
        {
            if (_handshakes.TryGetValue(connection, out var finished))
                finished.TrySetResult(true);
            HandshakeFinished?.Invoke(this, connection);
        }

        /// <summary>Serves a client of <see cref="Start"/>: closed unless its handshake completes in HandshakeTimeout.</summary>
        private async Task ServeAsync(TcpClient client)
        {
            var deadline = Stopwatch.StartNew();
            TimeSpan timeout = HandshakeTimeout;
            TlsConnectionBase connection = null;
            try
            {
                // Disposing the client is what ends a pending read on every framework.
                using (var expired = new CancellationTokenSource(timeout))
                using (expired.Token.Register(client.Dispose))
                    connection = await AcceptAsync(client.GetStream(), client.Client.RemoteEndPoint, expired.Token).ConfigureAwait(false);
                if (connection == null)
                    return;

                var finished = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                _handshakes[connection] = finished;
                connection.Closed += (_, _) => finished.TrySetResult(false);
                if (connection.IsHandshakeComplete || connection.IsClosed)
                    finished.TrySetResult(connection.IsHandshakeComplete);

                TimeSpan left = timeout - deadline.Elapsed;
                if (left < TimeSpan.Zero)
                    left = TimeSpan.Zero;
                if (await Task.WhenAny(finished.Task, Task.Delay(left)).ConfigureAwait(false) != finished.Task || !finished.Task.Result)
                {
                    connection.Close();
                    client.Dispose();
                }
            }
            catch (Exception)
            {
                connection?.Close();
                client.Dispose();
            }
            finally
            {
                if (connection != null)
                    _handshakes.TryRemove(connection, out _);
                Interlocked.Decrement(ref _pendingHandshakes);
            }
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
