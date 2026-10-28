using SharpDTLS.Protocol13;
using System;

namespace Dtls13Test.Tests
{
    /// <summary>The TLS 1.3 key schedule ("tls13 " labels) against RFC 8448 §3 (simple 1-RTT handshake).</summary>
    [TestClass]
    public sealed class TestTls13KeySchedule
    {
        private static byte[] Hex(string hex) => Convert.FromHexString(hex);

        [TestMethod]
        public void Rfc8448_HandshakeAndApplicationSecrets()
        {
            var suite = Dtls13CipherSuite.Get(0x1301).ForTls(); // TLS_AES_128_GCM_SHA256
            Assert.IsTrue(suite.IsTls);

            var handshake = Dtls13CryptoUtils.CalculateHandshakeKeys(new byte[32],
                Hex("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8"),
                Hex("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d"), suite);
            CollectionAssert.AreEqual(Hex("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"), handshake.ClientSecret);
            CollectionAssert.AreEqual(Hex("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"), handshake.ServerSecret);
            CollectionAssert.AreEqual(Hex("3fce516009c21727d0f2e4e86ee403bc"), handshake.ServerKey);
            CollectionAssert.AreEqual(Hex("5d313eb2671276ee13000b30"), handshake.ServerIv);

            var application = Dtls13CryptoUtils.CalculateApplicationKeys(new byte[32],
                Hex("9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13"), handshake.Secret, suite);
            CollectionAssert.AreEqual(Hex("9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5"), application.ClientSecret);
            CollectionAssert.AreEqual(Hex("a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643"), application.ServerSecret);
            CollectionAssert.AreEqual(Hex("9f02283b6c9c07efc26bb9f2ac92e356"), application.ServerKey);
            CollectionAssert.AreEqual(Hex("cf782b88dd83549aadf1e984"), application.ServerIv);
        }

        [TestMethod]
        public void TlsSuite_CarriesOverToKeyUpdates()
        {
            var suite = Dtls13CipherSuite.Get(0x1301).ForTls();
            var application = Dtls13CryptoUtils.CalculateApplicationKeys(new byte[32], new byte[32], new byte[32], suite);
            Assert.IsTrue(application.Suite.IsTls);
            Assert.IsTrue(Dtls13CryptoUtils.UpdateClientTrafficSecret(application).Suite.IsTls);
            Assert.IsTrue(Dtls13CryptoUtils.UpdateServerTrafficSecret(application).Suite.IsTls);
        }

        [TestMethod]
        public void DtlsSuites_KeepTheDtls13Prefix()
        {
            var dtls = Dtls13CipherSuite.Get(0x1301);
            Assert.IsFalse(dtls.IsTls);
            Assert.AreSame(dtls.ForTls(), dtls.ForTls());
            var tlsKeys = Dtls13CryptoUtils.CalculateHandshakeKeys(new byte[32], new byte[32], new byte[32], dtls.ForTls());
            var dtlsKeys = Dtls13CryptoUtils.CalculateHandshakeKeys(new byte[32], new byte[32], new byte[32], dtls);
            CollectionAssert.AreNotEqual(tlsKeys.ClientSecret, dtlsKeys.ClientSecret);
        }
    }
}

namespace Dtls13Test.Tests
{
    using SharpDTLS.Protocol13.Messages;
    using System.Linq;

    /// <summary>ClientHello, ServerHello and HelloRetryRequest in TLS form (RFC 8446 §4.1).</summary>
    [TestClass]
    public sealed class TestTls13Hellos
    {
        [TestMethod]
        public void ClientHello_TlsForm_RoundTrips()
        {
            var ch = new ClientHelloDatagram(new byte[32]) { Datagram = false, LegacySessionId = new byte[32] };
            ch.Extensions.RemoveAll(e => e is ClientSupportedVersions);
            ch.Extensions.Add(new ClientSupportedVersions(ClientSupportedVersions.Tls13));
            byte[] record = ch.ToBytes();
            CollectionAssert.AreEqual(new byte[] { 0x16, 0x03, 0x01 }, record.Take(3).ToArray());
            Assert.AreEqual(record.Length - 5, (record[3] << 8) | record[4]);
            Assert.AreEqual(0x01, record[5]);
            Assert.AreEqual(record.Length - 9, (record[6] << 16) | (record[7] << 8) | record[8]);
            CollectionAssert.AreEqual(new byte[] { 0x03, 0x03 }, record.Skip(9).Take(2).ToArray());

            var parsed = new ClientHelloDatagram { Datagram = false };
            parsed.FromBytes(record);
            CollectionAssert.AreEqual(ch.ClientRandom, parsed.ClientRandom);
            Assert.HasCount(32, parsed.LegacySessionId);
            CollectionAssert.AreEqual(ch.CipherSuites, parsed.CipherSuites);
            CollectionAssert.AreEqual(new[] { ClientSupportedVersions.Tls13 }, parsed.Extensions.OfType<ClientSupportedVersions>().Single().Versions);
            Assert.HasCount(ch.Extensions.Count, parsed.Extensions);
        }

        [TestMethod]
        public void ServerHelloAndRetry_TlsForm_RoundTrip()
        {
            var sh = new ServerHelloDatagram(new byte[32], 0x1302, new byte[32]) { Datagram = false, LegacySessionIdEcho = new byte[32] };
            sh.Extensions.RemoveAll(e => e is ServerSupportedVersions);
            sh.Extensions.Add(new ServerSupportedVersions(0x0304));
            byte[] record = sh.ToBytes();
            CollectionAssert.AreEqual(new byte[] { 0x16, 0x03, 0x03 }, record.Take(3).ToArray());
            Assert.AreEqual(0x02, record[5]);
            var parsed = new ServerHelloDatagram { Datagram = false };
            parsed.FromBytes(record);
            Assert.AreEqual(0x1302, parsed.SelectedCipherSuite);
            Assert.AreEqual(0x0304, parsed.Extensions.OfType<ServerSupportedVersions>().Single().Version);
            Assert.HasCount(32, parsed.LegacySessionIdEcho);

            var hrr = new HelloRetryRequest(0x1301, null, 0x0017, new byte[] { 1, 2, 3 }, datagram: false);
            var parsedHrr = new ServerHelloDatagram { Datagram = false };
            parsedHrr.FromBytes(hrr.ToBytes());
            Assert.IsTrue(HelloRetryRequest.IsHelloRetryRequest(parsedHrr));
            Assert.IsFalse(parsedHrr.Extensions.OfType<CookieExtension>().Any());
            CollectionAssert.AreEqual(new byte[] { 1, 2, 3 }, parsedHrr.LegacySessionIdEcho);
        }
    }
}
