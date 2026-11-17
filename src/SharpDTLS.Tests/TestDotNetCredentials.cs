using System;
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
        [DataRow(false, TlsVersion.Tls12)]
        [DataRow(false, TlsVersion.Tls13)]
        [DataRow(true, TlsVersion.Tls12)]
        [DataRow(true, TlsVersion.Tls13)]
        public async Task ServerAndClientOfTheirOwnKeys(bool ecdsa, ushort version)
        {
            using var serverCertificate = SelfSigned(ecdsa);
            using var clientCertificate = SelfSigned(ecdsa, "CN=client.test");
            X509Certificate2 seenByClient = null, seenByServer = null;
            using var server = new TlsServer(new ServerCredentials(serverCertificate))
            {
                RequireClientCertificate = true,
                ClientCertificateValidator = (certificate, chain) => (seenByServer = certificate) != null,
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
        public void ACertificateWithoutItsKeyIsRefused()
        {
            using var certificate = SelfSigned(ecdsa: true);
            using var publicOnly = Certificates.Load(certificate.RawData);
            Assert.ThrowsExactly<ArgumentException>(() => new ServerCredentials(publicOnly));
        }
    }
}
