using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace SharpDTLS.Tests
{
    /// <summary>Credentials of .NET's certificates, of their own keys: converted for BouncyCastle by the default crypto.</summary>
    [TestClass]
    public sealed class TestDotNetCredentials
    {
        private static readonly TimeSpan Timeout = TestTimeouts.Interop;

        internal static X509Certificate2 SelfSigned(bool ecdsa, string name = "CN=dotnet.test")
        {
            var request = ecdsa
                ? new CertificateRequest(name, ECDsa.Create(ECCurve.NamedCurves.nistP256), HashAlgorithmName.SHA256)
                : new CertificateRequest(name, RSA.Create(2048), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        }

        [TestMethod]
        [DataRow(false, TlsVersion.Tls12, false)]
        [DataRow(false, TlsVersion.Tls13, false)]
        [DataRow(true, TlsVersion.Tls12, false)]
        [DataRow(true, TlsVersion.Tls13, false)]
        [DataRow(false, TlsVersion.Tls12, true)]
        [DataRow(false, TlsVersion.Tls13, true)]
        [DataRow(true, TlsVersion.Tls12, true)]
        [DataRow(true, TlsVersion.Tls13, true)]
        public async Task ServerAndClientOfTheirOwnKeys(bool ecdsa, ushort version, bool netCrypto)
        {
            using var serverCertificate = SelfSigned(ecdsa);
            using var clientCertificate = SelfSigned(ecdsa, "CN=client.test");
            X509Certificate2 seenByClient = null, seenByServer = null;
            using var server = new TlsServer(new ServerCredentials(serverCertificate))
            {
                RequireClientCertificate = true,
                ClientCertificateValidator = (certificate, chain) => (seenByServer = certificate) != null,
                Crypto = netCrypto ? new NetTlsCrypto() : null,
            };
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var serverSide = Task.Run(async () =>
            {
                var tcp = await listener.AcceptTcpClientAsync();
                using var tls = await TlsStream.AcceptAsync(server, tcp.GetStream());
                return tls.Connection.PeerCertificate.Thumbprint;
            });

            using var client = new TcpClient();
            await client.ConnectAsync((IPEndPoint)listener.LocalEndpoint);
            using var stream = await TlsStream.ConnectAsync(client.GetStream(), c =>
            {
                c.MaximumVersion = version;
                c.ServerCertificateValidator = (certificate, chain) => (seenByClient = certificate) != null;
                c.ClientCredentials = new CertificateCredentials(clientCertificate);
                c.Crypto = netCrypto ? new NetTlsCrypto() : null;
            }).WaitAsync(Timeout);

            Assert.AreEqual(version, stream.NegotiatedVersion);
            Assert.AreEqual(serverCertificate.Thumbprint, seenByClient.Thumbprint);
            Assert.AreEqual(serverCertificate.Thumbprint, stream.Connection.PeerCertificate.Thumbprint);
            Assert.AreEqual(clientCertificate.Thumbprint, stream.Connection.LocalCertificate.Thumbprint);
            Assert.AreEqual(clientCertificate.Thumbprint, await serverSide.WaitAsync(Timeout));
            Assert.AreEqual(clientCertificate.Thumbprint, seenByServer.Thumbprint);
            listener.Stop();
        }

        [TestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public async Task RsaKeyTransport(bool netCrypto)
        {
            using var certificate = SelfSigned(ecdsa: false);
            var suites = new ushort[] { 0x009C }; // TLS_RSA_WITH_AES_128_GCM_SHA256
            using var server = new TlsServer(new ServerCredentials(certificate)) { CipherSuites = suites, Crypto = netCrypto ? new NetTlsCrypto() : null };
            Assert.AreEqual(TlsVersion.Tls12, await Connect(server, c => { c.MaximumVersion = TlsVersion.Tls12; c.CipherSuites = suites; c.Crypto = netCrypto ? new NetTlsCrypto() : null; }));
        }

        /// <summary>Static ECDH (ECDH_ECDSA) of the certificate's own EC key: .NET's ECDiffieHellman with NetTlsCrypto.</summary>
        [TestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public async Task StaticEcdh(bool netCrypto)
        {
            using var certificate = SelfSigned(ecdsa: true);
            var suites = new ushort[] { 0xC02D }; // TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256
            using var server = new TlsServer(new ServerCredentials(certificate)) { CipherSuites = suites, Crypto = netCrypto ? new NetTlsCrypto() : null };
            Assert.AreEqual(TlsVersion.Tls12, await Connect(server, c => { c.MaximumVersion = TlsVersion.Tls12; c.CipherSuites = suites; }));
        }

        [TestMethod]
        public async Task AKeyNotExportableIsOfNetTlsCryptoAlone()
        {
            if (Environment.OSVersion.Platform != PlatformID.Win32NT)
                Assert.Inconclusive("CNG keys are Windows'.");
            // a named key, of the user's store: the certificate refers to it rather than copying it, as it could not
            var parameters = new CngKeyCreationParameters { ExportPolicy = CngExportPolicies.None };
            parameters.Parameters.Add(new CngProperty("Length", BitConverter.GetBytes(2048), CngPropertyOptions.None));
            using var key = CngKey.Create(CngAlgorithm.Rsa, "SharpDTLS.Tests." + Guid.NewGuid(), parameters);
            try
            {
                using var rsa = new RSACng(key);
                using var certificate = new CertificateRequest("CN=cng.test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
                    .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

                using (var server = new TlsServer(new ServerCredentials(certificate)))
                    await Assert.ThrowsExactlyAsync<IOException>(() => Connect(server, null));
                using (var server = new TlsServer(new ServerCredentials(certificate)) { Crypto = new NetTlsCrypto() })
                    Assert.AreEqual(TlsVersion.Tls13, await Connect(server, null));
            }
            finally
            {
                key.Delete();
            }
        }

        // A certificate of a named key of the user's store that cannot be exported, as the Windows store, a TPM or a
        // smart card holds them; the key is deleted with the returned one.
        private static (X509Certificate2 Certificate, CngKey Key) NotExportable(bool ecdsa, string subject)
        {
            var parameters = new CngKeyCreationParameters { ExportPolicy = CngExportPolicies.None };
            if (!ecdsa)
                parameters.Parameters.Add(new CngProperty("Length", BitConverter.GetBytes(2048), CngPropertyOptions.None));
            var key = CngKey.Create(ecdsa ? CngAlgorithm.ECDsaP256 : CngAlgorithm.Rsa, "SharpDTLS.Tests." + Guid.NewGuid(), parameters);
            var request = ecdsa
                ? new CertificateRequest(subject, new ECDsaCng(key), HashAlgorithmName.SHA256)
                : new CertificateRequest(subject, new RSACng(key), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            return (request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1)), key);
        }

        /// <summary>Server and client certificates of keys that cannot be exported, of NetTlsCrypto, over TLS.</summary>
        [TestMethod]
        [DataRow(false, TlsVersion.Tls12)]
        [DataRow(false, TlsVersion.Tls13)]
        [DataRow(true, TlsVersion.Tls12)]
        [DataRow(true, TlsVersion.Tls13)]
        public async Task KeysNotExportableOverTls(bool ecdsa, ushort version)
        {
            if (Environment.OSVersion.Platform != PlatformID.Win32NT)
                Assert.Inconclusive("CNG keys are Windows'.");
            var (serverCertificate, serverKey) = NotExportable(ecdsa, "CN=server.cng.test");
            var (clientCertificate, clientKey) = NotExportable(ecdsa, "CN=client.cng.test");
            try
            {
                X509Certificate2 seenByServer = null;
                using var server = new TlsServer(new ServerCredentials(serverCertificate))
                {
                    Crypto = new NetTlsCrypto(),
                    RequireClientCertificate = true,
                    ClientCertificateValidator = (certificate, chain) => (seenByServer = certificate) != null,
                };
                Assert.AreEqual(version, await Connect(server, c =>
                {
                    c.MaximumVersion = version;
                    c.ClientCredentials = new CertificateCredentials(clientCertificate);
                    c.Crypto = new NetTlsCrypto();
                }));
                // in TLS 1.3 the client is done before the server has read its certificate
                Assert.IsTrue(System.Threading.SpinWait.SpinUntil(() => seenByServer != null, Timeout));
                Assert.AreEqual(clientCertificate.Thumbprint, seenByServer.Thumbprint);
            }
            finally
            {
                serverKey.Delete();
                clientKey.Delete();
            }
        }

        /// <summary>The same over DTLS 1.2 and 1.3, as WebRTC has it.</summary>
        [TestMethod]
        [DataRow(false, DtlsVersion.Dtls12)]
        [DataRow(false, DtlsVersion.Dtls13)]
        [DataRow(true, DtlsVersion.Dtls12)]
        [DataRow(true, DtlsVersion.Dtls13)]
        public void KeysNotExportableOverDtls(bool ecdsa, ushort version)
        {
            if (Environment.OSVersion.Platform != PlatformID.Win32NT)
                Assert.Inconclusive("CNG keys are Windows'.");
            var (serverCertificate, serverKey) = NotExportable(ecdsa, "CN=server.cng.test");
            var (clientCertificate, clientKey) = NotExportable(ecdsa, "CN=client.cng.test");
            try
            {
                var (serverTransport, clientTransport) = MockTransportPair.Create();
                X509Certificate2 seenByServer = null, seenByClient = null;
                var server = new DtlsServer(serverTransport, new ServerCredentials(serverCertificate))
                {
                    Crypto = new NetTlsCrypto(),
                    RequireClientCertificate = true,
                    ClientCertificateValidator = (certificate, chain) => (seenByServer = certificate) != null,
                };
                var client = new DtlsClient(clientTransport)
                {
                    MaximumVersion = version,
                    ClientCredentials = new CertificateCredentials(clientCertificate),
                    Crypto = new NetTlsCrypto(),
                    ServerCertificateValidator = (certificate, chain) => (seenByClient = certificate) != null,
                };
                string received = null;
                server.ApplicationDataReceived += (connection, data) => received = System.Text.Encoding.ASCII.GetString(data.ToArray());
                client.HandshakeFinished += (_, _) => client.SendApplicationData(System.Text.Encoding.ASCII.GetBytes("ping"));
                client.BeginHandshake();
                Assert.IsTrue(System.Threading.SpinWait.SpinUntil(() => received != null, Timeout));
                Assert.AreEqual("ping", received);
                Assert.AreEqual(version, client.NegotiatedVersion);
                Assert.AreEqual(serverCertificate.Thumbprint, seenByClient.Thumbprint);
                Assert.AreEqual(clientCertificate.Thumbprint, seenByServer.Thumbprint);
                client.Close();
            }
            finally
            {
                serverKey.Delete();
                clientKey.Delete();
            }
        }

        private static async Task<ushort> Connect(TlsServer server, Action<TlsClient> configure)
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            try
            {
                var serverSide = Task.Run(async () =>
                {
                    using var tcp = await listener.AcceptTcpClientAsync();
                    using var tls = await TlsStream.AcceptAsync(server, tcp.GetStream());
                });
                using var client = new TcpClient();
                await client.ConnectAsync((IPEndPoint)listener.LocalEndpoint);
                using var stream = await TlsStream.ConnectAsync(client.GetStream(), c =>
                {
                    c.ServerCertificateValidator = (certificate, chain) => true;
                    configure?.Invoke(c);
                }).WaitAsync(Timeout);
                return stream.NegotiatedVersion;
            }
            finally
            {
                listener.Stop();
            }
        }

        /// <summary>.NET's ECDHE against BouncyCastle's, each way, on every NIST curve.</summary>
        [TestMethod]
        [DataRow((ushort)0x0017, true, false)]
        [DataRow((ushort)0x0018, false, true)]
        [DataRow((ushort)0x0019, true, true)]
        public void EcdheOfNetTlsCrypto(ushort group, bool clientNet, bool serverNet)
        {
            var (serverTransport, clientTransport) = MockTransportPair.Create();
            var server = new DtlsServer(serverTransport) { SupportedGroups = new[] { group }, Crypto = serverNet ? new NetTlsCrypto() : null };
            var client = new DtlsClient(clientTransport)
            {
                KeyShareGroups = new[] { group },
                SupportedGroups = new[] { group },
                Crypto = clientNet ? new NetTlsCrypto() : null,
                ServerCertificateValidator = (certificate, chain) => true,
            };
            string received = null;
            server.ApplicationDataReceived += (connection, data) => received = System.Text.Encoding.ASCII.GetString(data.ToArray());
            client.HandshakeFinished += (_, _) => client.SendApplicationData(System.Text.Encoding.ASCII.GetBytes("ping"));
            client.BeginHandshake();
            Assert.IsTrue(System.Threading.SpinWait.SpinUntil(() => received != null, Timeout));
            Assert.AreEqual("ping", received);
            Assert.AreEqual(group, ((Protocol13.Tls13ServerConnection)server.Connections.Single()).NegotiatedGroup);
        }

        [TestMethod]
        public void ACertificateWithoutItsKeyIsRefused()
        {
            using var certificate = SelfSigned(ecdsa: true);
            using var publicOnly = Certificates.Load(certificate.RawData);
            Assert.ThrowsExactly<ArgumentException>(() => new ServerCredentials(publicOnly));
        }
    }
}
