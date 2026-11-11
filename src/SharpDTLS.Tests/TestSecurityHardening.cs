using Org.BouncyCastle.X509;
using SharpDTLS.Protocol13.Messages;
using SharpDTLS.UDP;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SharpDTLS.Tests
{
    /// <summary>Regression tests of the security review: spoofed records, unbounded state, defaults.</summary>
    [TestClass]
    public sealed class TestSecurityHardening
    {
        // A plaintext (epoch 0) handshake record of one fragment: msg_type, a declared length of 16, no body - malformed.
        private static byte[] SpoofedPlaintextHandshake(byte type, ushort messageSeq) => new byte[]
        {
            0x16, 0xFE, 0xFD, 0x00, 0x00, 0, 0, 0, 0, 0, 0x50, 0x00, 0x0C,
            type, 0x00, 0x00, 0x10, (byte)(messageSeq >> 8), (byte)messageSeq, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
        };

        private static (DtlsServer Server, DtlsClient Client, MockServerTransport ServerTransport, MockClientTransport ClientTransport,
            TlsConnectionBase ServerConnection) Connect(ushort version)
        {
            var (serverTransport, clientTransport) = MockTransportPair.Create();
            var server = new DtlsServer(serverTransport) { MaximumVersion = version };
            var client = new DtlsClient(clientTransport) { MaximumVersion = version };
            var connected = new TaskCompletionSource<TlsConnectionBase>(TaskCreationOptions.RunContinuationsAsynchronously);
            var clientDone = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            server.HandshakeFinished += (_, c) => connected.TrySetResult(c);
            client.HandshakeFinished += (_, _) => clientDone.TrySetResult(true);
            client.BeginHandshake();
            Assert.IsTrue(Task.WaitAll(new Task[] { connected.Task, clientDone.Task }, TestTimeouts.InProcess), "handshake");
            return (server, client, serverTransport, clientTransport, connected.Task.Result);
        }

        private static void AssertDataFlowsBothWays(DtlsServer server, DtlsClient client, TlsConnectionBase serverConnection)
        {
            var atServer = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            var atClient = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            server.ApplicationDataReceived += (_, e) => atServer.TrySetResult(Encoding.UTF8.GetString(e.Data));
            client.ApplicationDataReceived += (_, data) => atClient.TrySetResult(Encoding.UTF8.GetString(data));
            client.SendApplicationData(Encoding.UTF8.GetBytes("to the server"));
            serverConnection.SendApplicationData(Encoding.UTF8.GetBytes("to the client"));
            Assert.IsTrue(atServer.Task.Wait(TestTimeouts.InProcess));
            Assert.AreEqual("to the server", atServer.Task.Result);
            Assert.IsTrue(atClient.Task.Wait(TestTimeouts.InProcess));
            Assert.AreEqual("to the client", atClient.Task.Result);
        }

        [TestMethod]
        [DataRow(DtlsVersion.Dtls12)]
        [DataRow(DtlsVersion.Dtls13)]
        public void SpoofedPlaintextHandshakeRecords_DoNotEndAnEstablishedConnection(ushort version)
        {
            var (server, client, serverTransport, clientTransport, serverConnection) = Connect(version);

            // from the client's address to the server, and from the server's to the client: malformed records, a
            // Finished, a ClientHello, a ServerHello, at sequence numbers past and current
            foreach (byte type in new byte[] { 0x01, 0x02, 0x0B, 0x14, 0x10 })
            {
                foreach (ushort seq in new ushort[] { 0, 1, 2, 3, 4, 5, 6, 7 })
                {
                    serverTransport.InjectFromClient(SpoofedPlaintextHandshake(type, seq));
                    clientTransport.InjectFromServer(SpoofedPlaintextHandshake(type, seq));
                }
            }
            // a plaintext ChangeCipherSpec, alert and application data record of the wrong length
            foreach (byte contentType in new byte[] { 0x14, 0x15, 0x17 })
            {
                var record = new byte[] { contentType, 0xFE, 0xFD, 0, 0, 0, 0, 0, 0, 0, 0x60, 0x00, 0x03, 0x09, 0x09, 0x09 };
                serverTransport.InjectFromClient(record);
                clientTransport.InjectFromServer(record);
            }

            Assert.IsFalse(serverConnection.IsClosed, "the server's connection was ended");
            AssertDataFlowsBothWays(server, client, serverConnection);
        }

        [TestMethod]
        public void Dtls12CookieValidation_RefusesAWrongOrMissingCookie()
        {
            var now = DateTime.UtcNow;
            byte[] cookie = Protocol12.Dtls12CryptoUtils.CreateCookie(now, "192.0.2.1", 5000);
            Assert.IsTrue(Protocol12.Dtls12CryptoUtils.ValidateCookie(now, "192.0.2.1", 5000, cookie));
            Assert.IsFalse(Protocol12.Dtls12CryptoUtils.ValidateCookie(now, "192.0.2.1", 5001, cookie));
            Assert.IsFalse(Protocol12.Dtls12CryptoUtils.ValidateCookie(now, "192.0.2.1", 5000, cookie.AsSpan(0, cookie.Length - 1).ToArray()));
            Assert.IsFalse(Protocol12.Dtls12CryptoUtils.ValidateCookie(now, "192.0.2.1", 5000, null));
        }

        [TestMethod]
        public void ServerTransport_AnswersManySourcesWithoutAThreadOfEach()
        {
            using var transport = new ServerTransport(new IPEndPoint(IPAddress.Loopback, 0));
            transport.OnDataReceived += (sender, data) => transport.Send((EndPoint)sender, data);
            var sockets = new List<Socket>();
            try
            {
                for (int i = 0; i < 50; i++)
                {
                    var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp) { ReceiveTimeout = 5000 };
                    socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
                    sockets.Add(socket);
                    socket.SendTo(new byte[] { (byte)i }, transport.LocalEndpoint);
                }
                for (int i = 0; i < sockets.Count; i++)
                {
                    byte[] buffer = new byte[16];
                    Assert.AreEqual(1, sockets[i].Receive(buffer));
                    Assert.AreEqual((byte)i, buffer[0]);
                }
            }
            finally
            {
                foreach (var socket in sockets)
                    socket.Dispose();
            }
        }

        [TestMethod]
        public async Task TlsServer_ClosesAClientThatNeverCompletesItsHandshake()
        {
            using var server = new TlsServer { HandshakeTimeout = TimeSpan.FromSeconds(1) };
            server.Start(new IPEndPoint(IPAddress.Loopback, 0));
            foreach (byte[] sent in new[] { Array.Empty<byte>(), new byte[] { 0x16, 0x03, 0x01, 0x40, 0x00, 0x01 } })
            {
                using var tcp = new TcpClient();
                await tcp.ConnectAsync(IPAddress.Loopback, server.LocalEndpoint.Port);
                var stream = tcp.GetStream();
                await stream.WriteAsync(sent, 0, sent.Length);
                var read = Task.Run(() =>
                {
                    try { return stream.Read(new byte[16], 0, 16); }
                    catch (IOException) { return 0; }
                });
                Assert.IsTrue(read.Wait(TimeSpan.FromSeconds(10)), "closed by the server");
                Assert.AreEqual(0, read.Result);
            }
        }

        [TestMethod]
        public async Task TlsStream_StopsReadingWhileTheApplicationDoesNot()
        {
            using var server = new TlsServer();
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            try
            {
            var accepting = Task.Run(async () =>
            {
                var socket = await listener.AcceptTcpClientAsync();
                return await TlsStream.AcceptAsync(server, socket.GetStream());
            });
            using var tcp = new TcpClient();
            await tcp.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port);
            using var client = await TlsStream.ConnectAsync(tcp.GetStream(), c => c.ServerCertificateValidator = (certificate, chain) => true);
            using var serverStream = await accepting;

            // The client reads nothing: once its stream holds what it may, it stops reading the socket, and the
            // sender's writes block when TCP's buffers are full - long before all of it is sent.
            const int Total = 64 << 20;
            var writing = Task.Run(() =>
            {
                byte[] chunk = new byte[1 << 16];
                for (int sent = 0; sent < Total; sent += chunk.Length)
                    serverStream.Write(chunk, 0, chunk.Length);
            });
            Assert.IsFalse(writing.Wait(TimeSpan.FromSeconds(3)), "64 MiB were taken by a reader that read nothing");

            // reading drains it all
            byte[] buffer = new byte[1 << 16];
            long received = 0;
            while (received < Total)
            {
                int n = await client.ReadAsync(buffer, 0, buffer.Length);
                Assert.AreNotEqual(0, n);
                received += n;
            }
            Assert.IsTrue(writing.Wait(TestTimeouts.InProcess));
            }
            finally
            {
                listener.Stop();
            }
        }

        [TestMethod]
        public async Task TlsStream_TellsCloseNotifyFromATruncation()
        {
            foreach (bool closeNotify in new[] { true, false })
            {
                using var server = new TlsServer();
                var listener = new TcpListener(IPAddress.Loopback, 0);
                listener.Start();
                try
                {
                    var accepting = Task.Run(async () =>
                    {
                        var socket = await listener.AcceptTcpClientAsync();
                        return (socket, await TlsStream.AcceptAsync(server, socket.GetStream()));
                    });
                    using var tcp = new TcpClient();
                    await tcp.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port);
                    using var client = await TlsStream.ConnectAsync(tcp.GetStream(), c => c.ServerCertificateValidator = (certificate, chain) => true);
                    var (socket, serverStream) = await accepting;
                    if (closeNotify)
                        serverStream.Dispose();
                    else
                        socket.Client.Close(); // the TCP connection ends, no close_notify
                    var read = client.ReadAsync(new byte[16], 0, 16);
                    Assert.IsTrue(read.Wait(TestTimeouts.InProcess));
                    Assert.AreEqual(0, read.Result);
                    Assert.AreEqual(closeNotify, client.Connection.CloseNotifyReceived);
                }
                finally
                {
                    listener.Stop();
                }
            }
        }

        [TestMethod]
        public void DtlsServer_CapsTheConnectionsOfOneAddress()
        {
            var transport = new MultiSourceServerTransport();
            var server = new DtlsServer(transport) { MaxConnectionsPerAddress = 2 };
            int established = 0;
            server.HandshakeFinished += (_, _) => Interlocked.Increment(ref established);
            var clients = new List<DtlsClient>();
            for (int port = 1; port <= 4; port++)
            {
                var client = new DtlsClient(transport.ClientAt(new IPEndPoint(IPAddress.Parse("192.0.2.7"), port)));
                client.BeginHandshake();
                clients.Add(client);
            }
            Assert.IsTrue(SpinWait.SpinUntil(() => Volatile.Read(ref established) >= 2, TestTimeouts.InProcess));
            Thread.Sleep(500);
            Assert.AreEqual(2, Volatile.Read(ref established), "two connections of one address at most");

            var other = new DtlsClient(transport.ClientAt(new IPEndPoint(IPAddress.Parse("192.0.2.8"), 1)));
            other.BeginHandshake();
            Assert.IsTrue(SpinWait.SpinUntil(() => Volatile.Read(ref established) == 3, TestTimeouts.InProcess), "another address is answered");
        }

        /// <summary>A server transport of clients at addresses of the test's choosing, delivering in memory.</summary>
        private sealed class MultiSourceServerTransport : IServerTransport
        {
            private readonly Dictionary<string, Client> _clients = new();
            public event EventHandler<byte[]> OnDataReceived;

            public IClientTransport ClientAt(IPEndPoint endpoint)
            {
                var client = new Client(this, endpoint);
                lock (_clients)
                    _clients[endpoint.ToString()] = client;
                return client;
            }

            public void Send(EndPoint endpoint, byte[] buf)
            {
                Client client;
                lock (_clients)
                    _clients.TryGetValue(endpoint.ToString(), out client);
                client?.Deliver(buf);
            }

            private sealed class Client : IClientTransport
            {
                private readonly MultiSourceServerTransport _server;
                private readonly IPEndPoint _endpoint;
                public event EventHandler<byte[]> OnDataReceived;

                public Client(MultiSourceServerTransport server, IPEndPoint endpoint) => (_server, _endpoint) = (server, endpoint);
                public void Send(byte[] buf) => _server.OnDataReceived?.Invoke(_endpoint, buf);
                public void Deliver(byte[] buf) => OnDataReceived?.Invoke(null, buf);
            }
        }

        [TestMethod]
        public void Tls13Parsers_RefuseDuplicateExtensions()
        {
            // EncryptedExtensions (DTLS header) of two supported_groups extensions
            byte[] message = Convert.FromHexString("080000120000000000000012" + "0010" + "000a00040002001d" + "000a00040002001d" + "16");
            Assert.ThrowsExactly<DtlsException>(() => new EncryptedExtensionsDatagram().FromBytes(message));
        }

        /// <summary>Without a validator, a self-signed server certificate is refused. Not in parallel: the tests turn this off.</summary>
        [TestMethod]
        [DoNotParallelize]
        public void Client_WithoutAValidator_RefusesAnUntrustedCertificate()
        {
            CertificateValidatorDefaults.AcceptAnyPeerByDefault = false;
            try
            {
                var (serverTransport, clientTransport) = MockTransportPair.Create();
                var server = new DtlsServer(serverTransport);
                var client = new DtlsClient(clientTransport);
                var failed = new TaskCompletionSource<Exception>(TaskCreationOptions.RunContinuationsAsynchronously);
                bool finished = false;
                client.Failed += (_, ex) => failed.TrySetResult(ex);
                client.HandshakeFinished += (_, _) => finished = true;
                client.BeginHandshake();
                Assert.IsTrue(failed.Task.Wait(TestTimeouts.InProcess), "the handshake failed");
                Assert.IsFalse(finished);

                // a raw public key is refused without its validator
                Assert.IsFalse(CertificateValidatorDefaults.RawPublicKey(null, new byte[] { 1 }));
            }
            finally
            {
                CertificateValidatorDefaults.AcceptAnyPeerByDefault = true;
            }
        }

        [TestMethod]
        public void DefaultSuites_AreForwardSecretAeadAtTls12()
        {
            foreach (ushort id in CipherSuites.DefaultFor(TlsVersion.Tls12, TlsVersion.Tls12))
            {
                Assert.IsTrue(CipherSuites.TryGet(id, out var suite));
                Assert.AreEqual(CipherSuiteSecurity.Recommended, suite.Security, suite.Name);
            }
            foreach (ushort id in CipherSuites.DefaultFor(DtlsVersion.Dtls12, DtlsVersion.Dtls12))
            {
                Assert.IsTrue(CipherSuites.TryGet(id, out var suite));
                Assert.AreEqual(CipherSuiteSecurity.Recommended, suite.Security, suite.Name);
            }
        }
    }
}
