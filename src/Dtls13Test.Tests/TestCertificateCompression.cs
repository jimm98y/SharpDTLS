using SharpDTLS;
using SharpDTLS.DTLS13;
using SharpDTLS.DTLS13.Messages;
using System;
using System.Collections.Generic;
using System.IO.Compression;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Dtls13Test.Tests
{
    /// <summary>
    /// Certificate compression (RFC 8879) in DTLS 1.3. Self-tested only: none of the available peers implements it for
    /// DTLS (OpenSSL and BouncyCastle only for TLS 1.3, and the stock wolfSSL is built without it).
    /// </summary>
    [TestClass]
    public sealed class TestCertificateCompression
    {
        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);
        private static readonly Lazy<TestPki> _pki = new(() => new TestPki("Compression"));
        private static TestPki Pki => _pki.Value;

        private sealed record Outcome(Exception Error, Dtls13Client Client, Tls13ServerConnection Server, int ServerBytes);

        private static Outcome Run(IList<ushort> clientAlgorithms, IList<ushort> serverAlgorithms, bool clientAuth = false)
        {
            var pair = new ScriptedTransportPair();
            var leaf = Pki.Leaf(new[] { "server.test" });
            var server = new Dtls13Server(pair.Server, leaf.Key, leaf.Cert)
            {
                IntermediateCertificates = new[] { Pki.Intermediate.Cert }, CertificateCompressionAlgorithms = serverAlgorithms,
                RequireClientCertificate = clientAuth,
            };
            var client = new Dtls13Client(pair.Client) { CertificateCompressionAlgorithms = clientAlgorithms };
            if (clientAuth)
                (client.ClientCertificateKeyPair, client.ClientCertificate) = Pki.Leaf(commonName: "client", usage: Org.BouncyCastle.Asn1.X509.KeyPurposeID.id_kp_clientAuth);
            var done = new TaskCompletionSource<Exception>(TaskCreationOptions.RunContinuationsAsynchronously);
            client.HandshakeFinished += (_, _) => done.TrySetResult(null);
            client.Failed += (_, ex) => done.TrySetResult(ex);
            client.BeginHandshake();
            Assert.IsTrue(done.Task.Wait(Timeout), "the handshake neither completed nor failed");
            var connection = server.Connections.Single();
            if (done.Task.Result == null)
                Assert.IsTrue(SpinWait.SpinUntil(() => connection.IsHandshakeComplete, Timeout));
            return new Outcome(done.Task.Result, client, connection, pair.ServerSent.ToList().Sum(d => d.Length));
        }

        [DataRow(CertificateCompression.Brotli)]
        [DataRow(CertificateCompression.Zlib)]
        [TestMethod]
        public void ServerCertificate_IsCompressed(ushort algorithm)
        {
            var compressed = Run(new[] { algorithm }, CertificateCompression.Supported.ToList());
            Assert.IsNull(compressed.Error, compressed.Error?.ToString());
            Assert.AreEqual(algorithm, compressed.Client.CertificateCompressionAlgorithm);

            var plain = Run(null, CertificateCompression.Supported.ToList());
            Assert.IsNull(plain.Client.CertificateCompressionAlgorithm);
            Assert.IsLessThan(plain.ServerBytes, compressed.ServerBytes, "the server flight did not get smaller");
        }

        [TestMethod]
        public void ServerPreference_PicksTheAlgorithm()
        {
            var result = Run(new[] { CertificateCompression.Zlib, CertificateCompression.Brotli }, new[] { CertificateCompression.Brotli, CertificateCompression.Zlib });
            Assert.AreEqual(CertificateCompression.Brotli, result.Client.CertificateCompressionAlgorithm);
        }

        [TestMethod]
        public void ServerWithoutCompression_SendsThePlainCertificate()
        {
            var result = Run(CertificateCompression.Supported.ToList(), null);
            Assert.IsNull(result.Error, result.Error?.ToString());
            Assert.IsNull(result.Client.CertificateCompressionAlgorithm);
        }

        [TestMethod]
        public void ClientCertificate_IsCompressedWhenTheServerAllowsIt()
        {
            var result = Run(new[] { CertificateCompression.Zlib }, new[] { CertificateCompression.Brotli, CertificateCompression.Zlib }, clientAuth: true);
            Assert.IsNull(result.Error, result.Error?.ToString());
            Assert.AreEqual(CertificateCompression.Zlib, result.Server.CertificateCompressionAlgorithm);
            Assert.IsNotNull(result.Server.ClientCertificate);
        }

        [TestMethod]
        public void Decompression_IsBoundedAndChecked()
        {
            byte[] data = new byte[1000];
            byte[] zlib = CertificateCompression.Compress(CertificateCompression.Zlib, data);
            CollectionAssert.AreEqual(data, CertificateCompression.Decompress(CertificateCompression.Zlib, zlib, 1000));

            // Declared shorter (a decompression bomb) or longer than the data, over the cap, or not compressed at all.
            AssertAlert(AlertDescription.BadCertificate, () => CertificateCompression.Decompress(CertificateCompression.Zlib, zlib, 999));
            AssertAlert(AlertDescription.BadCertificate, () => CertificateCompression.Decompress(CertificateCompression.Zlib, zlib, 1001));
            AssertAlert(AlertDescription.BadCertificate, () => CertificateCompression.Decompress(CertificateCompression.Zlib, zlib, CertificateCompression.MaxUncompressedLength + 1));
            AssertAlert(AlertDescription.BadCertificate, () => CertificateCompression.Decompress(CertificateCompression.Brotli, new byte[] { 1, 2, 3, 4, 5 }, 10));
            AssertAlert(AlertDescription.IllegalParameter, () => CertificateCompression.Decompress(CertificateCompression.Zstd, zlib, 1000));
        }

        [TestMethod]
        public void UnofferedAlgorithm_IsIllegalParameter()
        {
            var certificate = new CertificateDatagram(new[] { Pki.Leaf().Cert.GetEncoded() });
            var message = new CompressedCertificateDatagram(CertificateCompression.Brotli, certificate);
            var parsed = new CompressedCertificateDatagram();
            parsed.FromBytes(message.ToBytes());
            AssertAlert(AlertDescription.IllegalParameter, () => parsed.Decompress(new[] { CertificateCompression.Zlib }));
            AssertAlert(AlertDescription.IllegalParameter, () => parsed.Decompress(null));
            CollectionAssert.AreEqual(certificate.CertificateChain[0], parsed.Decompress(new[] { CertificateCompression.Brotli }).CertificateChain[0]);
        }

        [TestMethod]
        public void Zlib_IsStandardRfc1950()
        {
            // Our zlib output is plain RFC 1950, which an independent decoder (DeflateStream after the 2-byte header) reads.
            byte[] data = System.Text.Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("certificate ", 50)));
            byte[] zlib = CertificateCompression.Compress(CertificateCompression.Zlib, data);
            Assert.AreEqual(0x78, zlib[0]);
            using var inflater = new DeflateStream(new System.IO.MemoryStream(zlib, 2, zlib.Length - 6), CompressionMode.Decompress);
            using var output = new System.IO.MemoryStream();
            inflater.CopyTo(output);
            CollectionAssert.AreEqual(data, output.ToArray());
        }

        private static void AssertAlert(AlertDescription expected, Action action)
            => Assert.AreEqual(expected, Assert.ThrowsExactly<DtlsException>(action).Alert);
    }
}
