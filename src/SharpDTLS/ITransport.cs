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
#if !NETCOREAPP
        // .NET Framework's sockets take arrays alone: buffers of the transport's own, grown once
        private byte[] _receiveBuffer, _sendBuffer;
#endif

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
#if NETCOREAPP
                    if (_socket.Connected)
                        return _socket.Receive(buffer);
                    EndPoint remote = new IPEndPoint(IPAddress.Any, 0);
                    return _socket.ReceiveFrom(buffer, SocketFlags.None, ref remote);
#else
                    if (_receiveBuffer == null || _receiveBuffer.Length < buffer.Length)
                        _receiveBuffer = new byte[buffer.Length];
                    int len;
                    if (_socket.Connected)
                    {
                        len = _socket.Receive(_receiveBuffer, 0, buffer.Length, SocketFlags.None);
                    }
                    else
                    {
                        EndPoint remote = new IPEndPoint(IPAddress.Any, 0);
                        len = _socket.ReceiveFrom(_receiveBuffer, 0, buffer.Length, SocketFlags.None, ref remote);
                    }
                    _receiveBuffer.AsSpan(0, len).CopyTo(buffer);
                    return len;
#endif
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

#if NETCOREAPP
            if (_remote == null)
                _socket.Send(buffer);
            else
                _socket.SendTo(buffer, SocketFlags.None, _remote);
#else
            lock (_receiveQueue)
            {
                if (_sendBuffer == null || _sendBuffer.Length < buffer.Length)
                    _sendBuffer = new byte[Math.Max(buffer.Length, _mtu)];
                buffer.CopyTo(_sendBuffer);
                if (_remote == null)
                    _socket.Send(_sendBuffer, 0, buffer.Length, SocketFlags.None);
                else
                    _socket.SendTo(_sendBuffer, 0, buffer.Length, SocketFlags.None, _remote);
            }
#endif
        }

        public virtual void Close()
        {
            _onClose?.Invoke(this);
        }
    }

    /// <summary>The datagrams of a DTLS server: received ones are handed over as spans valid only during the call.</summary>
    public interface IServerTransport
    {
        event DatagramHandler OnDataReceived;

        /// <summary>Sends one datagram; <paramref name="datagram"/> is not kept after the call.</summary>
        void Send(EndPoint endpoint, ReadOnlySpan<byte> datagram);
    }

    /// <summary>The datagrams of a DTLS client: received ones are handed over as spans valid only during the call.</summary>
    public interface IClientTransport
    {
        event DatagramHandler OnDataReceived;

        /// <summary>Sends one datagram; <paramref name="datagram"/> is not kept after the call.</summary>
        void Send(ReadOnlySpan<byte> datagram);
    }

    public class ServerTransport : IServerTransport, IDisposable
    {
        private readonly Socket _listenSocket;
        private readonly CancellationTokenSource _cts = new CancellationTokenSource();
        private volatile IPEndPoint _lastSender;
        public event DatagramHandler OnDataReceived;
#if NETCOREAPP
        // One endpoint per source address, so a datagram makes none; bounded, as any address can be spoofed.
        private const int MaxCachedAddresses = 4096;
        private readonly System.Collections.Generic.Dictionary<SocketAddress, IPEndPoint> _senders = new();
        private readonly ConcurrentDictionary<EndPoint, SocketAddress> _destinations = new();
#else
        private readonly byte[] _sendBuffer = new byte[UdpTransport.MTU];
#endif

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
#if NETCOREAPP
            var address = new SocketAddress(_listenSocket.AddressFamily);
#else
            EndPoint remoteEndpoint = new IPEndPoint(IPAddress.Any, 0);
#endif

            while (!_cts.IsCancellationRequested)
            {
                int length = 0;
                try
                {
                    // Poll, not ReceiveTimeout, which can lose a datagram arriving as it expires (see UdpTransport.Receive).
                    if (!_listenSocket.Poll(1_000_000, SelectMode.SelectRead))
                        continue;
#if NETCOREAPP
                    length = _listenSocket.ReceiveFrom(buffer, SocketFlags.None, address);
#else
                    length = _listenSocket.ReceiveFrom(buffer, ref remoteEndpoint);
#endif
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

                // Every datagram is handed to the handler on this one thread. No per-source state or thread is
                // made here: any source address can be spoofed, and the DTLS server keeps state only for peers
                // that passed its cookie exchange. Nothing one datagram does ends the loop.
                try
                {
#if NETCOREAPP
                    var sender = Sender(address);
#else
                    // copy: ReceiveFrom may reuse the endpoint instance on the next call
                    var sender = new IPEndPoint(((IPEndPoint)remoteEndpoint).Address, ((IPEndPoint)remoteEndpoint).Port);
#endif
                    _lastSender = sender;
                    OnDataReceived?.Invoke(sender, buffer.AsSpan(0, length));
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Receive failed: {ex.Message}");
                }
            }
        }

#if NETCOREAPP
        private IPEndPoint Sender(SocketAddress address)
        {
            if (_senders.TryGetValue(address, out var sender))
                return sender;
            if (_senders.Count >= MaxCachedAddresses)
                _senders.Clear();
            var key = new SocketAddress(address.Family, address.Size);
            address.Buffer.CopyTo(key.Buffer);
            sender = (IPEndPoint)new IPEndPoint(IPAddress.Any, 0).Create(key);
            _senders[key] = sender;
            return sender;
        }
#endif

        public void Send(EndPoint endpoint, ReadOnlySpan<byte> datagram)
        {
            if (endpoint == null)
                throw new ArgumentNullException(nameof(endpoint));
            if (datagram.Length > UdpTransport.MTU)
                throw new ArgumentException($"A datagram of {datagram.Length} bytes is larger than the MTU ({UdpTransport.MTU}).", nameof(datagram));
#if NETCOREAPP
            if (!_destinations.TryGetValue(endpoint, out var address))
            {
                if (_destinations.Count >= MaxCachedAddresses)
                    _destinations.Clear();
                address = _destinations.GetOrAdd(endpoint, static e => e.Serialize());
            }
            _listenSocket.SendTo(datagram, SocketFlags.None, address);
#else
            lock (_sendBuffer)
            {
                datagram.CopyTo(_sendBuffer);
                _listenSocket.SendTo(_sendBuffer, 0, datagram.Length, SocketFlags.None, endpoint);
            }
#endif
        }

        /// <summary>Sends to the source of the last datagram received.</summary>
        public void Send(ReadOnlySpan<byte> datagram)
        {
            Send(_lastSender ?? throw new InvalidOperationException("No datagram has been received yet."), datagram);
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
        public event DatagramHandler OnDataReceived;

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
                            OnDataReceived?.Invoke(remoteEndpoint, buffer.AsSpan(0, len));
                        }
                        catch (Exception ex)
                        {
                            Debug.WriteLine($"Receive handler failed: {ex.Message}");
                        }
                    }
                }
            });
        }

        public void Send(ReadOnlySpan<byte> datagram)
        {
            if (datagram.Length > _udpClientTransport.GetSendLimit())
                throw new ArgumentException($"A datagram of {datagram.Length} bytes is larger than the MTU ({UdpTransport.MTU}).", nameof(datagram));
            _udpClientTransport.Send(datagram);
        }

        public void Dispose()
        {
            _cts.Cancel();
            _socket.Dispose();
        }
    }
}
