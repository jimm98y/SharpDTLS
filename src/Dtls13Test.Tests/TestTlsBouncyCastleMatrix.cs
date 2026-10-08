using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using SharpDTLS;
using SharpDTLS.TLS12;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using CipherSuites = SharpDTLS.CipherSuites;

namespace Dtls13Test.Tests
{
    /// <summary>
    /// Every implemented TLS 1.1/1.2 cipher suite against BouncyCastle's TLS implementation over TCP, in both
    /// directions: covers suites OpenSSL lacks (Camellia-GCM, ARIA, SRP, fixed (EC)DH).
    /// </summary>
    [TestClass]
    [TestCategory("Interop")]
    public sealed class TestTlsBouncyCastleMatrix
    {
        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(15);

        public static IEnumerable<object[]> ImplementedSuites => CipherSuites.All.Select(s => new object[] { s.Id, s.Name });

        private static (CipherSuiteInfo Suite, BcTlsCrypto Crypto, ProtocolVersion BcVersion, ushort Version) Prepare(ushort id)
        {
            var suite = CipherSuites.Get(id);
            var crypto = new BcTlsCrypto(new SecureRandom());
            if (!TlsUtilities.IsSupportedCipherSuite(crypto, id))
                Assert.Inconclusive($"BouncyCastle does not support {suite.Name}");
            bool tls12 = suite.IsUsableWith(TlsVersion.Tls12);
            return (suite, crypto, tls12 ? ProtocolVersion.TLSv12 : ProtocolVersion.TLSv11, tls12 ? TlsVersion.Tls12 : TlsVersion.Tls11);
        }

        private static Task<T> RunBlocking<T>(Func<T> work)
            => Task.Factory.StartNew(work, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);

        [DynamicData(nameof(ImplementedSuites))]
        [TestMethod]
        public void SharpTlsClient_To_BouncyCastleServer(ushort id, string name)
        {
            var (suite, crypto, bcVersion, version) = Prepare(id);
            var (keyPair, certificate) = TestCredentials.For(suite);
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var bcServer = RunBlocking(() =>
            {
                using var tcp = listener.AcceptTcpClient();
                TlsServer peer = suite.RequiresPsk ? new BcPskTestServer(crypto, id, bcVersion, keyPair.Private, certificate.GetEncoded())
                    : suite.RequiresSrp ? new BcSrpTestServer(crypto, id, bcVersion, keyPair.Private, certificate.GetEncoded())
                    : new BcTestServer(crypto, id, bcVersion, keyPair.Private, certificate.GetEncoded());
                var protocol = new TlsServerProtocol(tcp.GetStream());
                protocol.Accept(peer);
                byte[] buffer = new byte[2048];
                int n = protocol.Stream.Read(buffer, 0, buffer.Length);
                string text = Encoding.UTF8.GetString(buffer, 0, n);
                byte[] reply = Encoding.UTF8.GetBytes("pong:" + text);
                protocol.Stream.Write(reply, 0, reply.Length);
                protocol.Stream.Flush();
                Thread.Sleep(100);
                return text;
            });

            try
            {
                var tcp = new TcpClient();
                tcp.Connect((IPEndPoint)listener.LocalEndpoint);
                var client = new Tls12Client(tcp.GetStream()) { MinimumVersion = version, MaximumVersion = version, CipherSuites = new List<ushort> { id } };
                if (suite.IsStaticKeyAgreement)
                    (client.ClientCertificateKeyPair, client.ClientCertificate) = TestCredentials.FixedClientFor(suite);
                if (suite.RequiresSrp)
                    (client.SrpIdentity, client.SrpPassword) = (TestCredentials.SrpIdentity, TestCredentials.SrpPassword);
                if (suite.RequiresPsk)
                    (client.PskIdentity, client.PskKey) = (TestCredentials.PskIdentity, TestCredentials.PskKey);
                var handshake = new TaskCompletionSource<Exception>(TaskCreationOptions.RunContinuationsAsynchronously);
                var received = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
                client.HandshakeFinished += (_, _) => handshake.TrySetResult(null);
                client.Failed += (_, ex) => handshake.TrySetResult(ex);
                client.ApplicationDataReceived += (_, d) => received.TrySetResult(Encoding.UTF8.GetString(d));
                client.BeginHandshake();
                Assert.IsTrue(handshake.Task.Wait(Timeout), $"{name}: handshake did not complete; {(bcServer.IsFaulted ? bcServer.Exception.GetBaseException().Message : "")}");
                Assert.IsNull(handshake.Task.Result, $"{name}: {handshake.Task.Result}; BouncyCastle: {(bcServer.IsFaulted ? bcServer.Exception.GetBaseException().Message : "")}");
                client.SendApplicationData(Encoding.UTF8.GetBytes("ping"));
                Assert.IsTrue(received.Task.Wait(Timeout), $"{name}: no reply; {(bcServer.IsFaulted ? bcServer.Exception.GetBaseException().Message : "")}");
                Assert.AreEqual("pong:ping", received.Task.Result);
                Assert.AreEqual(id, client.CipherSuite.Id);
            }
            finally
            {
                listener.Stop();
            }
        }

        [DynamicData(nameof(ImplementedSuites))]
        [TestMethod]
        public void BouncyCastleClient_To_SharpTlsServer(ushort id, string name)
        {
            var (suite, crypto, bcVersion, _) = Prepare(id);
            if (suite.IsStaticKeyAgreement)
                Assert.Inconclusive("BouncyCastle's TLS client fails to send the empty ClientKeyExchange of fixed (EC)DH "
                    + "authentication (TlsFatalAlert from CheckUint24 in HandshakeMessageOutput.Send); its DTLS client works");
            var (keyPair, certificate) = TestCredentials.For(suite);
            using var server = new Tls12Server(keyPair, certificate) { MinimumVersion = TlsVersion.Tls11, CipherSuites = new List<ushort> { id } };
            var (fixedKeyPair, fixedCertificate) = TestCredentials.FixedClientFor(suite);
            if (suite.IsStaticKeyAgreement)
                server.RequireClientCertificate = true;
            if (suite.RequiresSrp)
                server.SrpVerifierProvider = TestCredentials.ResolveSrp;
            if (suite.RequiresPsk)
                (server.PskIdentityResolver, server.PskIdentityHint) = (TestCredentials.ResolvePsk, TestCredentials.PskHint);
            SharpDTLS.DTLS12.Dtls12ServerConnection connection = null;
            server.ApplicationDataReceived += (_, e) =>
            {
                connection = e.Connection; // the connection is gone from Connections once the client hangs up
                e.Connection.SendApplicationData(Encoding.UTF8.GetBytes("pong:" + Encoding.UTF8.GetString(e.Data)));
            };
            server.Start(new IPEndPoint(IPAddress.Loopback, 0));

            var bcClient = RunBlocking(() =>
            {
                using var tcp = new TcpClient();
                tcp.Connect(server.LocalEndpoint);
                TlsClient peer = suite.RequiresPsk ? new BcPskTestClient(crypto, id, bcVersion)
                    : suite.RequiresSrp ? new BcSrpTestClient(crypto, id, bcVersion)
                    : new BcTestClient(crypto, id, bcVersion, fixedKeyPair, fixedCertificate);
                var protocol = new TlsClientProtocol(tcp.GetStream());
                protocol.Connect(peer);
                byte[] ping = Encoding.UTF8.GetBytes("ping");
                protocol.Stream.Write(ping, 0, ping.Length);
                protocol.Stream.Flush();
                byte[] buffer = new byte[2048];
                int n = protocol.Stream.Read(buffer, 0, buffer.Length);
                return Encoding.UTF8.GetString(buffer, 0, n);
            });

            Assert.IsTrue(bcClient.Wait(Timeout), $"{name}: BouncyCastle client did not finish");
            Assert.AreEqual("pong:ping", bcClient.Result);
            Assert.AreEqual(id, connection.CipherSuite.Id);
            if (suite.IsStaticKeyAgreement)
                Assert.AreEqual(fixedCertificate, connection.ClientCertificate, "fixed (EC)DH client authentication");
        }
    }
}
