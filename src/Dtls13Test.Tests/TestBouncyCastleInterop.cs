using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using AlertDescription = Org.BouncyCastle.Tls.AlertDescription;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;
using SharpDTLS;
using SharpDTLS.DTLS12;
using SharpSRTP.UDP;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Dtls13Test.Tests
{
    /// <summary>
    /// UDP transport for BouncyCastle's (blocking) DTLS implementation. A server-side transport
    /// connects to the first peer it hears from.
    /// </summary>
    internal sealed class BcUdpTransport : DatagramTransport
    {
        private readonly Socket _socket;
        private readonly System.Collections.Concurrent.ConcurrentQueue<string> _log;
        private readonly Stopwatch _clock = Stopwatch.StartNew();

        public BcUdpTransport(Socket socket, System.Collections.Concurrent.ConcurrentQueue<string> log = null)
        {
            _socket = socket;
            _log = log;
        }

        private void Log(string what) => _log?.Enqueue($"{_clock.ElapsedMilliseconds,6} ms BC {what}");

        public int GetReceiveLimit() => 1500;
        public int GetSendLimit() => 1200;

        public int Receive(byte[] buf, int off, int len, int waitMillis) => Receive(buf.AsSpan(off, len), waitMillis);

        public int Receive(Span<byte> buffer, int waitMillis)
        {
            try
            {
                _socket.ReceiveTimeout = Math.Max(1, waitMillis);
                if (_socket.Connected)
                {
                    int received = _socket.Receive(buffer);
                    Log($"recv {received} bytes type 0x{buffer[0]:X2}");
                    return received;
                }

                EndPoint from = new IPEndPoint(IPAddress.Any, 0);
                byte[] tmp = new byte[buffer.Length];
                int n = _socket.ReceiveFrom(tmp, ref from);
                _socket.Connect(from);
                tmp.AsSpan(0, n).CopyTo(buffer);
                Log($"recv first {n} bytes type 0x{buffer[0]:X2} from {from}");
                return n;
            }
            catch (SocketException)
            {
                return -1;
            }
            catch (ObjectDisposedException)
            {
                return -1;
            }
        }

        public void Send(byte[] buf, int off, int len) => Send(buf.AsSpan(off, len));
        public void Send(ReadOnlySpan<byte> buffer)
        {
            Log($"send {buffer.Length} bytes type 0x{buffer[0]:X2}");
            _socket.Send(buffer);
        }
        public void Close() => _socket.Close();
    }

    internal sealed class BcTestServer : DefaultTlsServer
    {
        private readonly int[] _suites;
        private readonly ProtocolVersion[] _versions;
        private readonly AsymmetricKeyParameter _privateKey;
        private readonly byte[] _certificate;

        public BcTestServer(BcTlsCrypto crypto, int suite, ProtocolVersion version, AsymmetricKeyParameter privateKey, byte[] certificate)
            : base(crypto)
        {
            _suites = new[] { suite };
            _versions = version.Only();
            _privateKey = privateKey;
            _certificate = certificate;
        }

        protected override ProtocolVersion[] GetSupportedVersions() => _versions;
        protected override int[] GetSupportedCipherSuites() => _suites;

        private Certificate Chain() => new Certificate(new[] { Crypto.CreateCertificate(_certificate) });

        private TlsCredentialedSigner Signer(short signatureAlgorithm)
        {
            var algorithm = TlsUtilities.IsTlsV12(m_context) ? new SignatureAndHashAlgorithm(HashAlgorithm.sha256, signatureAlgorithm) : null;
            return new BcDefaultTlsCredentialedSigner(new TlsCryptoParameters(m_context), (BcTlsCrypto)Crypto, _privateKey, Chain(), algorithm);
        }

        protected override TlsCredentialedSigner GetRsaSignerCredentials() => Signer(SignatureAlgorithm.rsa);
        protected override TlsCredentialedSigner GetDsaSignerCredentials() => Signer(SignatureAlgorithm.dsa);
        protected override TlsCredentialedSigner GetECDsaSignerCredentials() => Signer(SignatureAlgorithm.ecdsa);
        protected override TlsCredentialedDecryptor GetRsaEncryptionCredentials() => new BcDefaultTlsCredentialedDecryptor((BcTlsCrypto)Crypto, Chain(), _privateKey);

        // BouncyCastle implements static (EC)DH only with fixed (EC)DH client authentication.
        public override CertificateRequest GetCertificateRequest()
        {
            int keyExchange = TlsUtilities.GetKeyExchangeAlgorithm(m_selectedCipherSuite);
            if (keyExchange is not (Org.BouncyCastle.Tls.KeyExchangeAlgorithm.DH_DSS or Org.BouncyCastle.Tls.KeyExchangeAlgorithm.DH_RSA
                or Org.BouncyCastle.Tls.KeyExchangeAlgorithm.ECDH_ECDSA or Org.BouncyCastle.Tls.KeyExchangeAlgorithm.ECDH_RSA))
                return null;
            var types = new short[] { ClientCertificateType.rsa_fixed_dh, ClientCertificateType.dss_fixed_dh, ClientCertificateType.rsa_fixed_ecdh, ClientCertificateType.ecdsa_fixed_ecdh };
            var algorithms = TlsUtilities.IsTlsV12(m_context) ? TlsUtilities.GetDefaultSupportedSignatureAlgorithms(m_context) : null;
            return new CertificateRequest(types, algorithms, null);
        }

        // Static DH / ECDH suites authenticate with the certificate's key agreement key.
        public override TlsCredentials GetCredentials()
        {
            int keyExchange = TlsUtilities.GetKeyExchangeAlgorithm(m_selectedCipherSuite);
            return keyExchange is Org.BouncyCastle.Tls.KeyExchangeAlgorithm.DH_DSS or Org.BouncyCastle.Tls.KeyExchangeAlgorithm.DH_RSA or Org.BouncyCastle.Tls.KeyExchangeAlgorithm.ECDH_ECDSA or Org.BouncyCastle.Tls.KeyExchangeAlgorithm.ECDH_RSA
                ? new BcDefaultTlsCredentialedAgreement((BcTlsCrypto)Crypto, Chain(), _privateKey)
                : base.GetCredentials();
        }

        public override void NotifyClientCertificate(Certificate clientCertificate) { }
    }

    internal sealed class BcPskIdentityManager : TlsPskIdentityManager
    {
        public byte[] GetHint() => TestCredentials.PskHint;
        public byte[] GetPsk(byte[] identity) => TestCredentials.ResolvePsk(identity);
    }

    internal sealed class BcPskTestServer : PskTlsServer
    {
        private readonly int[] _suites;
        private readonly ProtocolVersion[] _versions;
        private readonly AsymmetricKeyParameter _privateKey;
        private readonly byte[] _certificate;

        public BcPskTestServer(BcTlsCrypto crypto, int suite, ProtocolVersion version, AsymmetricKeyParameter privateKey, byte[] certificate)
            : base(crypto, new BcPskIdentityManager())
        {
            _suites = new[] { suite };
            _versions = version.Only();
            _privateKey = privateKey;
            _certificate = certificate;
        }

        protected override ProtocolVersion[] GetSupportedVersions() => _versions;
        protected override int[] GetSupportedCipherSuites() => _suites;

        protected override TlsCredentialedDecryptor GetRsaEncryptionCredentials()
            => new BcDefaultTlsCredentialedDecryptor((BcTlsCrypto)Crypto, new Certificate(new[] { Crypto.CreateCertificate(_certificate) }), _privateKey);
    }

    internal sealed class BcPskTestClient : PskTlsClient
    {
        private readonly int[] _suites;
        private readonly ProtocolVersion[] _versions;

        public BcPskTestClient(BcTlsCrypto crypto, int suite, ProtocolVersion version)
            : base(crypto, TestCredentials.PskIdentity, TestCredentials.PskKey)
        {
            _suites = new[] { suite };
            _versions = version.Only();
        }

        protected override ProtocolVersion[] GetSupportedVersions() => _versions;
        protected override int[] GetSupportedCipherSuites() => _suites;
        public override TlsAuthentication GetAuthentication() => new AcceptAnyServer();

        private sealed class AcceptAnyServer : ServerOnlyTlsAuthentication
        {
            public override void NotifyServerCertificate(TlsServerCertificate serverCertificate) { }
        }
    }

    internal sealed class BcTestClient : DefaultTlsClient
    {
        private readonly int[] _suites;
        private readonly ProtocolVersion[] _versions;
        private readonly AsymmetricCipherKeyPair _fixedKeyPair;
        private readonly X509Certificate _fixedCertificate;

        /// <param name="fixedKeyPair">Key agreement key for fixed (EC)DH client authentication, or null.</param>
        public BcTestClient(BcTlsCrypto crypto, int suite, ProtocolVersion version, AsymmetricCipherKeyPair fixedKeyPair = null, X509Certificate fixedCertificate = null)
            : base(crypto)
        {
            _suites = new[] { suite };
            _versions = version.Only();
            _fixedKeyPair = fixedKeyPair;
            _fixedCertificate = fixedCertificate;
        }

        protected override ProtocolVersion[] GetSupportedVersions() => _versions;
        protected override int[] GetSupportedCipherSuites() => _suites;
        public override TlsAuthentication GetAuthentication() => new Authentication(this);

        private sealed class Authentication(BcTestClient owner) : TlsAuthentication
        {
            public void NotifyServerCertificate(TlsServerCertificate serverCertificate) { }

            public TlsCredentials GetClientCredentials(CertificateRequest certificateRequest)
            {
                if (owner._fixedKeyPair == null)
                    return null;
                var chain = new Certificate(new[] { owner.Crypto.CreateCertificate(owner._fixedCertificate.GetEncoded()) });
                return new BcDefaultTlsCredentialedAgreement((BcTlsCrypto)owner.Crypto, chain, owner._fixedKeyPair.Private);
            }
        }
    }

    /// <summary>
    /// Every implemented DTLS 1.0/1.2 cipher suite against BouncyCastle's independent DTLS implementation,
    /// in both directions. Covers suites OpenSSL does not implement (Camellia-GCM, ARIA-CBC) or that the
    /// installed OpenSSL lacks (3DES).
    /// </summary>
    [TestClass]
    [TestCategory("Interop")]
    public sealed class TestBouncyCastleInterop
    {
        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(15);

        public static IEnumerable<object[]> ImplementedSuites => CipherSuites.All.Select(s => new object[] { s.Id, s.Name });

        private static (CipherSuiteInfo Suite, BcTlsCrypto Crypto, ProtocolVersion BcVersion, ushort Version) Prepare(ushort id)
        {
            var suite = CipherSuites.Get(id);
            var crypto = new BcTlsCrypto(new SecureRandom());
            if (!TlsUtilities.IsSupportedCipherSuite(crypto, id))
                Assert.Inconclusive($"BouncyCastle does not support {suite.Name}");
            bool dtls12 = suite.IsUsableWith(DtlsVersion.Dtls12);
            return (suite, crypto, dtls12 ? ProtocolVersion.DTLSv12 : ProtocolVersion.DTLSv10, dtls12 ? DtlsVersion.Dtls12 : DtlsVersion.Dtls10);
        }

        private static Socket LoopbackSocket()
        {
            var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            return socket;
        }

        private static Task<T> RunBlocking<T>(Func<T> work)
            => Task.Factory.StartNew(work, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);

        [DynamicData(nameof(ImplementedSuites))]
        [TestMethod]
        public void SharpDtlsClient_To_BouncyCastleServer(ushort id, string name)
        {
            var (suite, crypto, bcVersion, version) = Prepare(id);
            var (keyPair, certificate) = TestCredentials.For(suite);

            using var serverSocket = LoopbackSocket();
            int port = ((IPEndPoint)serverSocket.LocalEndPoint).Port;
            var log = new System.Collections.Concurrent.ConcurrentQueue<string>();
            var bcServer = RunBlocking(() =>
            {
                TlsServer bcServerPeer = suite.RequiresPsk
                    ? new BcPskTestServer(crypto, id, bcVersion, keyPair.Private, certificate.GetEncoded())
                    : new BcTestServer(crypto, id, bcVersion, keyPair.Private, certificate.GetEncoded());
                var dtls = new DtlsServerProtocol().Accept(bcServerPeer, new BcUdpTransport(serverSocket, log));
                byte[] buffer = new byte[2048];
                int n = dtls.Receive(buffer, 0, buffer.Length, (int)Timeout.TotalMilliseconds);
                string text = n > 0 ? Encoding.UTF8.GetString(buffer, 0, n) : null;
                byte[] reply = Encoding.UTF8.GetBytes("pong:" + text);
                dtls.Send(reply, 0, reply.Length);
                return text;
            });

            using var transport = new ClientTransport(new IPEndPoint(IPAddress.Loopback, port));
            var client = new Dtls12Client(transport) { MinimumVersion = version, MaximumVersion = version, CipherSuites = new List<ushort> { id } };
            if (suite.IsStaticKeyAgreement)
                (client.ClientCertificateKeyPair, client.ClientCertificate) = TestCredentials.FixedClientFor(suite);
            if (suite.RequiresPsk)
            {
                client.PskIdentity = TestCredentials.PskIdentity;
                client.PskKey = TestCredentials.PskKey;
            }
            var handshake = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            var received = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            client.HandshakeFinished += (_, _) => handshake.TrySetResult(true);
            client.Failed += (_, ex) => handshake.TrySetException(ex);
            client.ApplicationDataReceived += (_, data) => received.TrySetResult(Encoding.UTF8.GetString(data));
            var clock = Stopwatch.StartNew();
            transport.OnDataReceived += (_, d) => log.Enqueue($"{clock.ElapsedMilliseconds,6} ms client recv {d.Length} bytes type 0x{d[0]:X2}");

            client.BeginHandshake();
            if (!handshake.Task.Wait(Timeout))
            {
                serverSocket.Close(); // unblock the BouncyCastle thread
                try { bcServer.Wait(TimeSpan.FromSeconds(2)); } catch (AggregateException) { }
                Assert.Fail($"{name}: handshake did not complete; BouncyCastle server: {(bcServer.IsFaulted ? bcServer.Exception.GetBaseException().Message : bcServer.Status.ToString())}\n" + string.Join("\n", log));
            }
            client.SendApplicationData(Encoding.UTF8.GetBytes("ping"));

            Assert.IsTrue(bcServer.Wait(Timeout), $"{name}: BouncyCastle server did not finish");
            Assert.AreEqual("ping", bcServer.Result);
            Assert.IsTrue(received.Task.Wait(Timeout), $"{name}: client did not receive the reply");
            Assert.AreEqual("pong:ping", received.Task.Result);
        }

        [DynamicData(nameof(ImplementedSuites))]
        [TestMethod]
        public void BouncyCastleClient_To_SharpDtlsServer(ushort id, string name)
        {
            var (suite, crypto, bcVersion, version) = Prepare(id);
            var (keyPair, certificate) = TestCredentials.For(suite);

            using var transport = new ServerTransport(new IPEndPoint(IPAddress.Loopback, 0));
            var server = new Dtls12Server(transport, keyPair, certificate) { MinimumVersion = DtlsVersion.Dtls10, CipherSuites = new List<ushort> { id } };
            var (fixedKeyPair, fixedCertificate) = TestCredentials.FixedClientFor(suite);
            if (suite.IsStaticKeyAgreement)
                server.RequireClientCertificate = true;
            if (suite.RequiresPsk)
            {
                server.PskIdentityResolver = TestCredentials.ResolvePsk;
                server.PskIdentityHint = TestCredentials.PskHint;
            }
            server.ApplicationDataReceived += (_, e) => server.SendApplicationData(e.RemoteEndPoint, Encoding.UTF8.GetBytes("pong:" + Encoding.UTF8.GetString(e.Data)));

            using var clientSocket = LoopbackSocket();
            clientSocket.Connect(new IPEndPoint(IPAddress.Loopback, transport.LocalEndpoint.Port));
            var bcClient = RunBlocking(() =>
            {
                TlsClient bcClientPeer = suite.RequiresPsk ? new BcPskTestClient(crypto, id, bcVersion) : new BcTestClient(crypto, id, bcVersion, fixedKeyPair, fixedCertificate);
                var dtls = new DtlsClientProtocol().Connect(bcClientPeer, new BcUdpTransport(clientSocket));
                byte[] ping = Encoding.UTF8.GetBytes("ping");
                dtls.Send(ping, 0, ping.Length);
                byte[] buffer = new byte[2048];
                int n = dtls.Receive(buffer, 0, buffer.Length, (int)Timeout.TotalMilliseconds);
                return n > 0 ? Encoding.UTF8.GetString(buffer, 0, n) : null;
            });

            Assert.IsTrue(bcClient.Wait(Timeout), $"{name}: BouncyCastle client did not finish");
            Assert.AreEqual("pong:ping", bcClient.Result);
            Assert.AreEqual(id, server.Connections.Single().CipherSuite.Id);
            if (suite.IsStaticKeyAgreement)
                Assert.AreEqual(fixedCertificate, server.Connections.Single().ClientCertificate, "fixed (EC)DH client authentication");
        }
    }
}
