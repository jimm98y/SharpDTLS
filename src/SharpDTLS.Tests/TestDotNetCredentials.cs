using System;
using System.IO;
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

        [TestMethod]
        public void ACertificateWithoutItsKeyIsRefused()
        {
            using var certificate = SelfSigned(ecdsa: true);
            using var publicOnly = Certificates.Load(certificate.RawData);
            Assert.ThrowsExactly<ArgumentException>(() => new ServerCredentials(publicOnly));
        }
    }
}
