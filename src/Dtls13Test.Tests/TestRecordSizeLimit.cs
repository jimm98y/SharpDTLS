using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using SharpDTLS;
using SharpDTLS.DTLS12;
using SharpDTLS.DTLS13;
using SharpSRTP.UDP;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AlertDescription = SharpDTLS.AlertDescription;
using CipherSuites = SharpDTLS.CipherSuites;

namespace Dtls13Test.Tests
{
    /// <summary>record_size_limit (RFC 8449) and max_fragment_length (RFC 6066 §4) in both engines.</summary>
    [TestClass]
    public sealed class TestRecordSizeLimit
    {
        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

        private sealed class Endpoints
        {
            public ScriptedTransportPair Pair;
            public TlsConnectionBase Client;
            public TlsConnectionBase Server;
            public readonly List<byte[]> ClientReceived = new();
            public readonly List<byte[]> ServerReceived = new();
        }

        private static Endpoints Connect(int version, int? clientLimit = null, int? clientMfl = null, int? serverLimit = null)
        {
            var result = new Endpoints { Pair = new ScriptedTransportPair() };
            var done = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            Func<TlsConnectionBase> serverConnection;
            if (version == 12)
            {
                var server = new Dtls12Server(result.Pair.Server) { RecordSizeLimit = serverLimit };
                server.ApplicationDataReceived += (_, e) => { lock (result.ServerReceived) result.ServerReceived.Add(e.Data); };
                var client = new Dtls12Client(result.Pair.Client) { RecordSizeLimit = clientLimit, MaxFragmentLength = clientMfl };
                client.HandshakeFinished += (_, _) => done.TrySetResult(true);
                client.Failed += (_, ex) => done.TrySetException(ex);
                result.Client = client;
                serverConnection = () => server.Connections.Single();
            }
            else
            {
                var server = new Dtls13Server(result.Pair.Server) { RecordSizeLimit = serverLimit };
                server.ApplicationDataReceived += (_, e) => { lock (result.ServerReceived) result.ServerReceived.Add(e.Data); };
                var client = new Dtls13Client(result.Pair.Client) { RecordSizeLimit = clientLimit, MaxFragmentLength = clientMfl };
                client.HandshakeFinished += (_, _) => done.TrySetResult(true);
                client.Failed += (_, ex) => done.TrySetException(ex);
                result.Client = client;
                serverConnection = () => server.Connections.Single();
            }
            result.Client.ApplicationDataReceived += (_, d) => { lock (result.ClientReceived) result.ClientReceived.Add(d); };
            ((dynamic)result.Client).BeginHandshake();
            Assert.IsTrue(done.Task.Wait(Timeout), "handshake did not complete");
            result.Server = serverConnection();
            Assert.IsTrue(SpinWait.SpinUntil(() => result.Server.IsHandshakeComplete, Timeout));
            return result;
        }

        private static void Exchange(Endpoints e, int clientBytes, int serverBytes)
        {
            e.Client.SendApplicationData(new byte[clientBytes]);
            e.Server.SendApplicationData(new byte[serverBytes]);
            Assert.IsTrue(SpinWait.SpinUntil(() => { lock (e.ServerReceived) return e.ServerReceived.Any(d => d.Length == clientBytes); }, Timeout));
            Assert.IsTrue(SpinWait.SpinUntil(() => { lock (e.ClientReceived) return e.ClientReceived.Any(d => d.Length == serverBytes); }, Timeout));
        }

        // Protected DTLS 1.3 records: 5-byte unified header, 16-byte tag, the content type, the payload.
        private static IEnumerable<byte[]> ProtectedRecords(IEnumerable<byte[]> datagrams)
            => datagrams.ToList().SelectMany(d => DtlsRecordSplitter.Split(d)).Where(r => (r[0] & 0xE0) == 0x20);

        private static IEnumerable<byte[]> PlaintextHandshakeRecords(IEnumerable<byte[]> datagrams)
            => datagrams.ToList().SelectMany(d => DtlsRecordSplitter.Split(d)).Where(r => r[0] == 0x16 && r[3] == 0 && r[4] == 0);

        [DataRow(12)]
        [DataRow(13)]
        [TestMethod]
        public void RecordSizeLimits_ApplyToTheOtherSide(int version)
        {
            var e = Connect(version, clientLimit: 256, serverLimit: 512);
            Assert.AreEqual(512, e.Client.MaxApplicationDataSize);
            Assert.AreEqual(256, e.Server.MaxApplicationDataSize);
            Exchange(e, 512, 256);
            Assert.ThrowsExactly<ArgumentException>(() => e.Server.SendApplicationData(new byte[257]));
            Assert.ThrowsExactly<ArgumentException>(() => e.Client.SendApplicationData(new byte[513]));
        }

        [TestMethod]
        public void SmallestRecordSizeLimit_FragmentsTheServerFlight()
        {
            // 64 bytes: the server's EncryptedExtensions, Certificate, CertificateVerify and Finished in many records.
            var e = Connect(13, clientLimit: 64);
            var records = ProtectedRecords(e.Pair.ServerSent).ToList();
            Assert.IsGreaterThan(10, records.Count);
            Assert.IsTrue(records.All(r => r.Length <= 5 + 16 + 1 + 64), string.Join(",", records.Select(r => r.Length)));
            Exchange(e, 100, 64);
        }

        [DataRow(12)]
        [DataRow(13)]
        [TestMethod]
        public void MaxFragmentLength_AppliesBothWays(int version)
        {
            var e = Connect(version, clientMfl: 512);
            Assert.AreEqual(512, e.Client.MaxApplicationDataSize);
            Assert.AreEqual(512, e.Server.MaxApplicationDataSize);
            Exchange(e, 512, 512);
            Assert.ThrowsExactly<ArgumentException>(() => e.Client.SendApplicationData(new byte[513]));

            // It covers handshake records too, the unprotected ones included.
            Assert.IsTrue(PlaintextHandshakeRecords(e.Pair.ServerSent).All(r => r.Length - 13 <= 512));
            if (version == 13)
                Assert.IsTrue(ProtectedRecords(e.Pair.ServerSent).All(r => r.Length <= 5 + 16 + 1 + 512));
        }

        [DataRow(12)]
        [DataRow(13)]
        [TestMethod]
        public void BothOffered_RecordSizeLimitWins(int version)
        {
            var e = Connect(version, clientLimit: 1000, clientMfl: 512);
            Assert.AreEqual(1000, e.Server.MaxApplicationDataSize);
            Assert.AreEqual(TlsConnectionBase.MaxRecordPayload, e.Client.MaxApplicationDataSize);
            Exchange(e, 4000, 1000);
        }

        [DataRow(12)]
        [DataRow(13)]
        [TestMethod]
        public void NothingNegotiated_AllowsFullRecords(int version)
        {
            var e = Connect(version);
            Assert.AreEqual(16384, e.Client.MaxApplicationDataSize);
            Exchange(e, 16384, 16384);
            Assert.ThrowsExactly<ArgumentException>(() => e.Client.SendApplicationData(new byte[16385]));
        }

        [DataRow(12)]
        [DataRow(13)]
        [TestMethod]
        public void OversizedRecord_IsRecordOverflow(int version)
        {
            var e = Connect(version, clientLimit: 200, serverLimit: 100);
            var failed = new TaskCompletionSource<Exception>(TaskCreationOptions.RunContinuationsAsynchronously);
            e.Server.Failed += (_, ex) => failed.TrySetResult(ex);

            // A misbehaving client that ignores the server's limit.
            typeof(TlsConnectionBase).GetProperty("PeerRecordLimit", BindingFlags.Instance | BindingFlags.NonPublic).SetValue(e.Client, 16384);
            e.Client.SendApplicationData(new byte[101]);
            Assert.IsTrue(failed.Task.Wait(Timeout));
            Assert.AreEqual(AlertDescription.RecordOverflow, ((DtlsException)failed.Task.Result).Alert);
        }

        [TestMethod]
        public void ServerAnswers_AreChecked()
        {
            Assert.AreEqual(AlertDescription.UnsupportedExtension, Assert.ThrowsExactly<DtlsException>(
                () => RecordSizeNegotiation.Complete(new RecordSizeLimitExtension(100), null, null, null, false)).Alert);
            Assert.AreEqual(AlertDescription.IllegalParameter, Assert.ThrowsExactly<DtlsException>(
                () => RecordSizeNegotiation.Complete(new RecordSizeLimitExtension(100), new MaxFragmentLengthExtension(512), 100, 512, false)).Alert);
            Assert.AreEqual(AlertDescription.IllegalParameter, Assert.ThrowsExactly<DtlsException>(
                () => RecordSizeNegotiation.Complete(null, new MaxFragmentLengthExtension(1024), null, 512, false)).Alert);
            Assert.AreEqual(AlertDescription.IllegalParameter, Assert.ThrowsExactly<DtlsException>(
                () => RecordSizeNegotiation.Complete(null, new MaxFragmentLengthExtension(512), null, null, true)).Alert);
            // DTLS 1.3 values count the content type; values above 2^14 + 1 are capped.
            Assert.AreEqual((16384, 300), RecordSizeNegotiation.Complete(new RecordSizeLimitExtension(40000), null, 300, null, true));
            Assert.AreEqual((99, 300), RecordSizeNegotiation.Complete(new RecordSizeLimitExtension(100), null, 300, null, true));
        }

        [TestMethod]
        public void MalformedExtensions_AreRejected()
        {
            Assert.AreEqual(AlertDescription.IllegalParameter, Assert.ThrowsExactly<DtlsException>(
                () => new RecordSizeLimitExtension().Read(0, new byte[] { 0x00, 0x1c, 0x00, 0x02, 0x00, 63 })).Alert);
            Assert.AreEqual(AlertDescription.DecodeError, Assert.ThrowsExactly<DtlsException>(
                () => new RecordSizeLimitExtension().Read(0, new byte[] { 0x00, 0x1c, 0x00, 0x01, 0x40 })).Alert);
            Assert.AreEqual(AlertDescription.IllegalParameter, Assert.ThrowsExactly<DtlsException>(
                () => new MaxFragmentLengthExtension().Read(0, new byte[] { 0x00, 0x01, 0x00, 0x01, 5 })).Alert);
            Assert.ThrowsExactly<InvalidOperationException>(() => RecordSizeNegotiation.Validate(63, null));
            Assert.ThrowsExactly<InvalidOperationException>(() => RecordSizeNegotiation.Validate(16385, null));
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => RecordSizeNegotiation.Validate(null, 8192));
        }

        // ── Interop ──────────────────────────────────────────────────────────────────────────

        private static void Handshake(Action begin, Action<Action> onSuccess, Action<Action<Exception>> onFailure, string context)
        {
            var done = new TaskCompletionSource<Exception>(TaskCreationOptions.RunContinuationsAsynchronously);
            onSuccess(() => done.TrySetResult(null));
            onFailure(ex => done.TrySetResult(ex));
            begin();
            Assert.IsTrue(done.Task.Wait(Timeout), "handshake timed out:\n" + context);
            Assert.IsNull(done.Task.Result, done.Task.Result?.ToString());
        }

        private static string Line(char c, int length) => new string(c, length - 1) + "\n";

        [TestCategory("Interop")]
        [TestMethod]
        public void OpenSsl_MaxFragmentLength_BothDirections()
        {
            OpenSsl.RequireOpenSsl();
            string dir = OpenSsl.NewTempDirectory();
            var (key, cert) = TestCredentials.For(CertificateKeyType.Rsa);
            string certPath = OpenSsl.WritePem(dir, "cert.pem", cert);
            string keyPath = OpenSsl.WritePem(dir, "key.pem", key.Private);

            using (var server = OpenSslProcess.StartServer(p => $"s_server -dtls1_2 -accept 127.0.0.1:{p} -cert {certPath} -key {keyPath}", dir, Timeout, out int port))
            {
                Assert.IsTrue(server.WaitForOutput("ACCEPT", Timeout), server.Output);
                using var transport = new ClientTransport(new IPEndPoint(IPAddress.Loopback, port));
                var client = new Dtls12Client(transport) { MaxFragmentLength = 512 };
                Handshake(client.BeginHandshake, s => client.HandshakeFinished += (_, _) => s(), f => client.Failed += (_, ex) => f(ex), server.Output);
                Assert.AreEqual(512, client.MaxApplicationDataSize);
                client.SendApplicationData(Encoding.ASCII.GetBytes(Line('a', 512)));
                Assert.IsTrue(server.WaitForOutput(new string('a', 511), Timeout), server.Output);
            }

            // OpenSSL enforces the length on what it receives, so our server's flight must be fragmented to 512.
            using var serverTransport = new ServerTransport(new IPEndPoint(IPAddress.Loopback, 0));
            var dtlsServer = new Dtls12Server(serverTransport, key, cert);
            using var openSslClient = new OpenSslProcess($"s_client -dtls1_2 -connect 127.0.0.1:{serverTransport.LocalEndpoint.Port} -maxfraglen 512", dir);
            Assert.IsTrue(SpinWait.SpinUntil(() => dtlsServer.Connections.Any(c => c.IsHandshakeComplete), Timeout), openSslClient.Output);
            var connection = dtlsServer.Connections.Single();
            Assert.AreEqual(512, connection.MaxApplicationDataSize);
            connection.SendApplicationData(Encoding.ASCII.GetBytes(Line('b', 512)));
            Assert.IsTrue(openSslClient.WaitForOutput(new string('b', 511), Timeout), openSslClient.Output);
        }

        [TestCategory("Interop")]
        [TestMethod]
        public void WolfSsl_MaxFragmentLength_BothDirections()
        {
            WolfSsl.RequireWolfSsl();
            string dir = OpenSsl.NewTempDirectory();
            var (key, cert) = Dtls13CryptoUtils.GenerateSelfSignedEcCertificate();
            string certPath = OpenSsl.WritePem(dir, "cert.pem", cert);
            string keyPath = OpenSsl.WritePem(dir, "key.pem", key.Private);

            using (var server = OpenSslProcess.StartServer(p => $"server {p} {certPath} {keyPath}", dir, Timeout, out int port, WolfSsl.Harness))
            {
                Assert.IsTrue(server.WaitForOutput("ACCEPT", Timeout), server.Output);
                using var transport = new ClientTransport(new IPEndPoint(IPAddress.Loopback, port));
                var client = new Dtls13Client(transport) { MaxFragmentLength = 512 };
                Handshake(client.BeginHandshake, s => client.HandshakeFinished += (_, _) => s(), f => client.Failed += (_, ex) => f(ex), server.Output);
                Assert.AreEqual(512, client.MaxApplicationDataSize);
                client.SendApplicationData(Encoding.ASCII.GetBytes(Line('c', 512)));
                Assert.IsTrue(server.WaitForOutput("RECV:" + new string('c', 511), Timeout), server.Output);
            }

            using var serverTransport = new ServerTransport(new IPEndPoint(IPAddress.Loopback, 0));
            var dtlsServer = new Dtls13Server(serverTransport);
            using var wolfClient = new OpenSslProcess($"client {serverTransport.LocalEndpoint.Port} -mfl 1", dir, WolfSsl.Harness);
            Assert.IsTrue(wolfClient.WaitForOutput("CONNECTED", Timeout), wolfClient.Output);
            var connection = dtlsServer.Connections.Single();
            Assert.AreEqual(512, connection.MaxApplicationDataSize);
            connection.SendApplicationData(Encoding.ASCII.GetBytes(Line('d', 512)));
            Assert.IsTrue(wolfClient.WaitForOutput("RECV:" + new string('d', 511), Timeout), wolfClient.Output);
        }

        [TestCategory("Interop")]
        [TestMethod]
        public void BouncyCastle_RecordSizeLimit()
        {
            const ushort suite = 0xC02F; // ECDHE-RSA-AES128-GCM-SHA256
            var crypto = new BcTlsCrypto(new SecureRandom());
            var (keyPair, certificate) = TestCredentials.For(CipherSuites.Get(suite));

            // BouncyCastle client with a 256-byte limit, our server.
            using (var transport = new ServerTransport(new IPEndPoint(IPAddress.Loopback, 0)))
            {
                var server = new Dtls12Server(transport, keyPair, certificate) { RecordSizeLimit = 1000 };
                server.ApplicationDataReceived += (_, e) => server.SendApplicationData(e.RemoteEndPoint, new byte[256]);
                using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
                socket.Connect(new IPEndPoint(IPAddress.Loopback, transport.LocalEndpoint.Port));
                var bc = Task.Factory.StartNew(() =>
                {
                    var dtls = new DtlsClientProtocol().Connect(new BcTestClient(crypto, suite, ProtocolVersion.DTLSv12) { RecordSizeLimit = 256 }, new BcUdpTransport(socket));
                    // BouncyCastle's client does not lower its send limit for the server's record_size_limit; 1000 fits ours.
                    dtls.Send(new byte[1000], 0, 1000);
                    byte[] buffer = new byte[2048];
                    return dtls.Receive(buffer, 0, buffer.Length, (int)Timeout.TotalMilliseconds);
                }, TaskCreationOptions.LongRunning);
                Assert.IsTrue(bc.Wait(Timeout), "BouncyCastle client did not finish");
                Assert.AreEqual(256, server.Connections.Single().MaxApplicationDataSize);
                Assert.AreEqual(256, bc.Result);
            }

            // Our client with a 256-byte limit, BouncyCastle's DTLS server, which does not negotiate record_size_limit: without
            // its answer our limit is not in force (RFC 8449 §4), so its full-size records are fine.
            using var serverSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            serverSocket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            var bcServer = Task.Factory.StartNew(() =>
            {
                var peer = new BcTestServer(crypto, suite, ProtocolVersion.DTLSv12, keyPair.Private, certificate.GetEncoded());
                var dtls = new DtlsServerProtocol().Accept(peer, new BcUdpTransport(serverSocket));
                byte[] buffer = new byte[2048];
                int n = dtls.Receive(buffer, 0, buffer.Length, (int)Timeout.TotalMilliseconds);
                dtls.Send(new byte[dtls.GetSendLimit()], 0, dtls.GetSendLimit());
                return n;
            }, TaskCreationOptions.LongRunning);

            using var clientTransport = new ClientTransport(new IPEndPoint(IPAddress.Loopback, ((IPEndPoint)serverSocket.LocalEndPoint).Port));
            var client = new Dtls12Client(clientTransport) { RecordSizeLimit = 256, CipherSuites = new List<ushort> { suite } };
            var received = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
            client.ApplicationDataReceived += (_, d) => received.TrySetResult(d.Length);
            Handshake(client.BeginHandshake, s => client.HandshakeFinished += (_, _) => s(), f => client.Failed += (_, ex) => f(ex),
                bcServer.IsFaulted ? bcServer.Exception.GetBaseException().Message : "");
            client.SendApplicationData(new byte[1000]); // within the test transport's 1500-byte datagrams
            Assert.IsTrue(received.Task.Wait(Timeout), bcServer.IsFaulted ? bcServer.Exception.GetBaseException().ToString() : "no reply");
            Assert.AreEqual(TlsConnectionBase.MaxRecordPayload, client.MaxApplicationDataSize);
            Assert.IsGreaterThan(256, received.Task.Result);
        }
    }
}
