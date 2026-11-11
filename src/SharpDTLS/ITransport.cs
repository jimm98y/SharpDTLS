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

// SharpSRTP
// Copyright (C) 2025 Lukas Volf
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

using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace SharpDTLS.UDP
{
    public interface ITransport
    {
        void Send(byte[] buf, int off, int len);
        int Receive(byte[] buf, int off, int len, int waitMillis);
    }

    /// <summary>
    /// UDP transport.
    /// </summary>
    public class UdpTransport : ITransport
    {
        public const int MAX_RECEIVE_QUEUE_ITEMS = 32;
        public const int MTU = 1472; // 1500 - 20 (IP) - 8 (UDP)

        private readonly Socket _socket;
        private readonly EndPoint _remote;
        private readonly int _mtu = MTU;
        private readonly Action<UdpTransport> _onClose;
        private readonly BlockingCollection<byte[]> _receiveQueue = new BlockingCollection<byte[]>();

        public string RemoteEndpoint { get { return _remote.ToString(); } }
        public DateTime LastReceived { get; private set; } = DateTime.UtcNow;
        public DateTime LastSent { get; private set; } = DateTime.UtcNow;
        public DateTime LastUsed { get { return LastReceived > LastSent ? LastReceived : LastSent; } }

        public UdpTransport(Socket socket, EndPoint remote = null, int mtu = MTU, Action<UdpTransport> onClose = null)
        {
            this._socket = socket ?? throw new ArgumentNullException(nameof(socket));
            this._remote = remote;
            this._mtu = mtu;
            this._onClose = onClose;
        }

        public bool TryAddToReceiveQueue(byte[] data, int maxReceiveQueueSize = MAX_RECEIVE_QUEUE_ITEMS)
        {
            LastReceived = DateTime.UtcNow;
            if (_receiveQueue.Count > maxReceiveQueueSize)
            {
                return false;
            }
            _receiveQueue.Add(data);
            return true;
        }

        public virtual int GetReceiveLimit()
        {
            return _mtu;
        }

        public virtual int GetSendLimit()
        {
            return _mtu;
        }

        public virtual int Receive(byte[] buf, int off, int len, int waitMillis)
        {
            return Receive(buf.AsSpan(off, len), waitMillis);
        }

        public virtual int Receive(Span<byte> buffer, int waitMillis)
        {
            if (_remote == null)
            {
                try
                {
                    // Poll, not ReceiveTimeout: a receive that times out leaves a Windows socket in an indeterminate
                    // state, and a datagram arriving at that moment can be lost.
                    if (!this._socket.Poll(PollMicroseconds(waitMillis), SelectMode.SelectRead))
                        return -1;
                    EndPoint remote = new IPEndPoint(IPAddress.Any, 0);
                    var byteBuffer = buffer.ToArray();
                    int len = this._socket.ReceiveFrom(byteBuffer, ref remote);
                    byteBuffer.AsSpan().CopyTo(buffer);
                    return len;
                }
                catch (SocketException)
                {
                    return -1;
                }
            }
            else
            {
                if (_receiveQueue.TryTake(out byte[] data, waitMillis))
                {
                    data.AsSpan().CopyTo(buffer);
                    return data.Length;
                }
                return -1;
            }
        }

        /// <summary>Socket.Poll microseconds for a wait in milliseconds, where 0 or less waits indefinitely (-1).</summary>
        internal static int PollMicroseconds(int waitMillis) => waitMillis <= 0 ? -1 : (int)Math.Min((long)waitMillis * 1000, int.MaxValue);

        public virtual void Send(byte[] buf, int off, int len)
        {
            if (len > GetSendLimit())
            {
                /*
                 * RFC 4347 4.1.1. "If the application attempts to send a record larger than the MTU,
                 * the DTLS implementation SHOULD generate an error, thus avoiding sending a packet
                 * which will be fragmented."
                 */
                throw new Exception();
            }

            Send(buf.AsSpan(off, len));
        }

        public virtual void Send(ReadOnlySpan<byte> buffer)
        {
            LastSent = DateTime.UtcNow;

            if (_remote == null)
            {
                _socket.Send(buffer.ToArray());
            }
            else
            {
                _socket.SendTo(buffer.ToArray(), _remote);
            }
        }

        public virtual void Close()
        {
            _onClose?.Invoke(this);
        }
    }

    public interface IServerTransport
    {
        event EventHandler<byte[]> OnDataReceived;
        void Send(EndPoint endpoint, byte[] buf);
    }

    public interface IClientTransport
    {
        event EventHandler<byte[]> OnDataReceived;
        void Send(byte[] buf);
    }

    public class ServerTransport : IServerTransport, IDisposable
    {
        private readonly Socket _listenSocket;
        private readonly CancellationTokenSource _cts = new CancellationTokenSource();
        private volatile IPEndPoint _lastSender;
        public event EventHandler<byte[]> OnDataReceived;

        /// <summary>The bound local endpoint (useful when binding to port 0).</summary>
        public IPEndPoint LocalEndpoint { get; }

        public ServerTransport() : this(IPEndPoint.Parse("0.0.0.0:8888"))
        {
        }

        public ServerTransport(IPEndPoint localEndpoint)
        {
            _listenSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                // disables the SocketException on client hard crash
                const int SIO_UDP_CONNRESET = -1744830452;
                _listenSocket.IOControl((IOControlCode)SIO_UDP_CONNRESET, new byte[] { 0, 0, 0, 0 }, null);
                _listenSocket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.PacketInformation, true);
            }

            _listenSocket.Bind(localEndpoint);
            LocalEndpoint = (IPEndPoint)_listenSocket.LocalEndPoint;

            // The receive loop blocks, so it runs on a dedicated thread rather than a thread-pool thread.
            StartLongRunning(ListenLoop);
        }

        private void ListenLoop()
        {
            byte[] buffer = new byte[UdpTransport.MTU];
            EndPoint remoteEndpoint = new IPEndPoint(IPAddress.Any, 0);

            while (!_cts.IsCancellationRequested)
            {
                int length = 0;
                try
                {
                    // Poll, not ReceiveTimeout, which can lose a datagram arriving as it expires (see UdpTransport.Receive).
                    if (!_listenSocket.Poll(1_000_000, SelectMode.SelectRead))
                        continue;
                    length = _listenSocket.ReceiveFrom(buffer, ref remoteEndpoint);
                }
                catch (SocketException ex)
                {
                    Debug.WriteLine(ex.Message);
                    continue;
                }
                catch (ObjectDisposedException)
                {
                    return;
                }

                if (length <= 0)
                    continue;

                // copy: ReceiveFrom may reuse the endpoint instance on the next call
                var sender = new IPEndPoint(((IPEndPoint)remoteEndpoint).Address, ((IPEndPoint)remoteEndpoint).Port);
                _lastSender = sender;

                // Every datagram is handed to the handler on this one thread. No per-source state or thread is
                // made here: any source address can be spoofed, and the DTLS server keeps state only for peers
                // that passed its cookie exchange.
                try
                {
                    OnDataReceived?.Invoke(sender, buffer.AsSpan(0, length).ToArray());
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Receive handler failed: {ex.Message}");
                }
            }
        }

        public void Send(EndPoint endpoint, byte[] buf)
        {
            if (endpoint == null)
                throw new ArgumentNullException(nameof(endpoint));
            if (buf.Length > UdpTransport.MTU)
                throw new ArgumentException($"A datagram of {buf.Length} bytes is larger than the MTU ({UdpTransport.MTU}).", nameof(buf));
            _listenSocket.SendTo(buf, endpoint);
        }

        /// <summary>Sends to the source of the last datagram received.</summary>
        public void Send(byte[] buf)
        {
            Send(_lastSender ?? throw new InvalidOperationException("No datagram has been received yet."), buf);
        }

        public void Dispose()
        {
            _cts.Cancel();
            _listenSocket.Dispose();
        }

        internal static void StartLongRunning(Action loop)
            => Task.Factory.StartNew(loop, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
    }

    public class ClientTransport : IClientTransport, IDisposable
    {
        private readonly Socket _socket;
        private readonly UdpTransport _udpClientTransport;
        private readonly CancellationTokenSource _cts = new CancellationTokenSource();
        public event EventHandler<byte[]> OnDataReceived;

        public ClientTransport() : this(IPEndPoint.Parse("127.0.0.1:8888"))
        {
        }

        public ClientTransport(IPEndPoint remoteEndpoint)
        {
            _socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            _socket.Connect(remoteEndpoint);

            _udpClientTransport = new UdpTransport(_socket);
            ServerTransport.StartLongRunning(() =>
            {
                byte[] buffer = new byte[UdpTransport.MTU];
                while (!_cts.IsCancellationRequested)
                {
                    int len;
                    try
                    {
                        len = _udpClientTransport.Receive(buffer, 0, buffer.Length, 1000);
                    }
                    catch (ObjectDisposedException)
                    {
                        return;
                    }

                    if (len > 0)
                    {
                        try
                        {
                            OnDataReceived?.Invoke(remoteEndpoint, buffer.AsSpan(0, len).ToArray());
                        }
                        catch (Exception ex)
                        {
                            Debug.WriteLine($"Receive handler failed: {ex.Message}");
                        }
                    }
                }
            });
        }

        public void Send(byte[] buf)
        {
            _udpClientTransport.Send(buf, 0, buf.Length);
        }

        public void Dispose()
        {
            _cts.Cancel();
            _socket.Dispose();
        }
    }
}
