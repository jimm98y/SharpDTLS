using SharpDTLS.Protocol12;
using SharpDTLS.Protocol12.Messages;
using System;
using System.Collections.Generic;

namespace Dtls13Test.Tests
{
    [TestClass]
    public sealed class TestDtls12
    {
        // ── ClientHello ──────────────────────────────────────────────────────

        [TestMethod]
        public void ClientHello_RoundTrip()
        {
            var random = new byte[32];
            random[0] = 0xAB; random[31] = 0xCD;

            // No-arg constructor gives empty Extensions and default CipherSuites.
            var ch = new ClientHelloDatagram
            {
                ClientRandom          = random,
                CipherSuites          = new List<ushort> { 0xC02F, 0xC030 },
                RecordSequenceNumber  = 5,
                MessageSequenceNumber = 2,
            };
            byte[] bytes = ch.ToBytes();

            var ch2 = new ClientHelloDatagram();
            ch2.FromBytes(bytes);

            Assert.AreEqual(Convert.ToHexString(random), Convert.ToHexString(ch2.ClientRandom));
            Assert.HasCount(2, ch2.CipherSuites);
            Assert.AreEqual(0xC02F, ch2.CipherSuites[0]);
            Assert.AreEqual(0xC030, ch2.CipherSuites[1]);
            Assert.AreEqual(5,      ch2.RecordSequenceNumber);
            Assert.AreEqual(2,      ch2.MessageSequenceNumber);
            Assert.HasCount(0,      ch2.Cookie);
            Assert.AreEqual(Convert.ToHexString(bytes), Convert.ToHexString(ch2.ToBytes()));
        }

        [TestMethod]
        public void ClientHello_WithCookie_RoundTrip()
        {
            var random = new byte[32];
            var cookie = new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };

            var ch = new ClientHelloDatagram
            {
                ClientRandom = random,
                Cookie       = cookie,
                CipherSuites = new List<ushort> { 0xC02F },
            };
            byte[] bytes = ch.ToBytes();

            var ch2 = new ClientHelloDatagram();
            ch2.FromBytes(bytes);

            Assert.AreEqual(Convert.ToHexString(cookie), Convert.ToHexString(ch2.Cookie));
            Assert.HasCount(1,      ch2.CipherSuites);
            Assert.AreEqual(0xC02F, ch2.CipherSuites[0]);
            Assert.AreEqual(Convert.ToHexString(bytes), Convert.ToHexString(ch2.ToBytes()));
        }

        [TestMethod]
        public void ClientHello_WithDefaultExtensions_RoundTrip()
        {
            // Constructor with includeSrtp=true adds default extensions.
            var ch = new ClientHelloDatagram(includeSrtp: true);
            ch.ClientRandom = new byte[32];
            byte[] bytes = ch.ToBytes();

            var ch2 = new ClientHelloDatagram();
            ch2.FromBytes(bytes);

            Assert.AreEqual(Convert.ToHexString(bytes), Convert.ToHexString(ch2.ToBytes()));
        }

        [TestMethod]
        public void ClientHello_VersionBytes_AreDtls12()
        {
            var ch = new ClientHelloDatagram { ClientRandom = new byte[32] };
            byte[] bytes = ch.ToBytes();
            // Record version at offset 1-2 must be 0xFEFD (DTLS 1.2)
            Assert.AreEqual(0xFE, bytes[1]);
            Assert.AreEqual(0xFD, bytes[2]);
            // client_version at offset 25-26 must also be 0xFEFD
            Assert.AreEqual(0xFE, bytes[25]);
            Assert.AreEqual(0xFD, bytes[26]);
        }

        // ── ServerHello ──────────────────────────────────────────────────────

        [TestMethod]
        public void ServerHello_RoundTrip()
        {
            var random = new byte[32];
            random[0] = 0x11; random[31] = 0x22;

            var sh = new ServerHelloDatagram(0xC02F, random)
            {
                RecordSequenceNumber  = 3,
                MessageSequenceNumber = 1,
            };
            byte[] bytes = sh.ToBytes();

            var sh2 = new ServerHelloDatagram();
            sh2.FromBytes(bytes);

            Assert.AreEqual(Convert.ToHexString(random), Convert.ToHexString(sh2.ServerRandom));
            Assert.AreEqual(0xC02F, sh2.SelectedCipherSuite);
            Assert.AreEqual(3,      sh2.RecordSequenceNumber);
            Assert.AreEqual(1,      sh2.MessageSequenceNumber);
            Assert.AreEqual(Convert.ToHexString(bytes), Convert.ToHexString(sh2.ToBytes()));
        }

        [TestMethod]
        public void ServerHello_WithSrtp_RoundTrip()
        {
            var sh = new ServerHelloDatagram(0xC02F, new byte[32], includeSrtp: true, srtpProfile: 0x0001);
            byte[] bytes = sh.ToBytes();

            var sh2 = new ServerHelloDatagram();
            sh2.FromBytes(bytes);

            Assert.AreEqual(0xC02F, sh2.SelectedCipherSuite);
            Assert.AreEqual(Convert.ToHexString(bytes), Convert.ToHexString(sh2.ToBytes()));
        }

        [TestMethod]
        public void ServerHello_VersionBytes_AreDtls12()
        {
            var sh = new ServerHelloDatagram(0xC02F, new byte[32]);
            byte[] bytes = sh.ToBytes();
            Assert.AreEqual(0xFE, bytes[1]);
            Assert.AreEqual(0xFD, bytes[2]);
            Assert.AreEqual(0xFE, bytes[25]);
            Assert.AreEqual(0xFD, bytes[26]);
        }

        // ── HelloVerifyRequest ────────────────────────────────────────────────

        [TestMethod]
        public void HelloVerifyRequest_RoundTrip()
        {
            var cookie = new byte[] { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
            var hvr = new HelloVerifyRequestDatagram(cookie) { RecordSequenceNumber = 7 };
            byte[] bytes = hvr.ToBytes();

            var hvr2 = new HelloVerifyRequestDatagram();
            hvr2.FromBytes(bytes);

            Assert.AreEqual(Convert.ToHexString(cookie), Convert.ToHexString(hvr2.Cookie));
            Assert.AreEqual(7, hvr2.RecordSequenceNumber);
            Assert.AreEqual(Convert.ToHexString(bytes), Convert.ToHexString(hvr2.ToBytes()));
        }

        [TestMethod]
        public void HelloVerifyRequest_VersionBytes_AreDtls12()
        {
            var hvr = new HelloVerifyRequestDatagram(new byte[] { 0x01 });
            byte[] bytes = hvr.ToBytes();
            // Record version at offset 1-2 must be 0xFEFD (DTLS 1.2)
            Assert.AreEqual(0xFE, bytes[1]);
            Assert.AreEqual(0xFD, bytes[2]);
            // server_version field at offset 25-26 must also be 0xFEFD
            Assert.AreEqual(0xFE, bytes[25]);
            Assert.AreEqual(0xFD, bytes[26]);
        }

        // ── PRF ──────────────────────────────────────────────────────────────

        [TestMethod]
        public void Prf_IsDeterministic()
        {
            var secret = new byte[48];
            var seed   = new byte[32];
            seed[0] = 0x42;

            byte[] a = Dtls12CryptoUtils.PRF(secret, "test label", seed, 48);
            byte[] b = Dtls12CryptoUtils.PRF(secret, "test label", seed, 48);

            Assert.AreEqual(Convert.ToHexString(a), Convert.ToHexString(b));
        }

        [TestMethod]
        public void Prf_ProducesCorrectLength()
        {
            var secret = new byte[48];
            var seed   = new byte[32];

            byte[] output = Dtls12CryptoUtils.PRF(secret, "key expansion", seed, 40);

            Assert.HasCount(40, output);
        }

        [TestMethod]
        public void Prf_ShorterOutputIsPrefixOfLonger()
        {
            var secret = new byte[48];
            var seed   = new byte[32];

            byte[] shorter = Dtls12CryptoUtils.PRF(secret, "key expansion", seed, 20);
            byte[] longer  = Dtls12CryptoUtils.PRF(secret, "key expansion", seed, 60);

            // First 20 bytes must match
            for (int i = 0; i < 20; i++)
                Assert.AreEqual(shorter[i], longer[i], $"Mismatch at byte {i}");
        }

        // ── MasterSecret / DeriveKeys ─────────────────────────────────────────

        [TestMethod]
        public void MasterSecret_Is48Bytes_AndDeterministic()
        {
            var preMaster    = new byte[32]; preMaster[0] = 0x01;
            var clientRandom = new byte[32]; clientRandom[0] = 0x02;
            var serverRandom = new byte[32]; serverRandom[0] = 0x03;

            byte[] ms1 = Dtls12CryptoUtils.CalculateMasterSecret(preMaster, clientRandom, serverRandom);
            byte[] ms2 = Dtls12CryptoUtils.CalculateMasterSecret(preMaster, clientRandom, serverRandom);

            Assert.HasCount(48, ms1);
            Assert.AreEqual(Convert.ToHexString(ms1), Convert.ToHexString(ms2));
        }

        [TestMethod]
        public void DeriveKeys_ProducesCorrectLengths()
        {
            var master       = new byte[48]; master[0] = 0x55;
            var clientRandom = new byte[32];
            var serverRandom = new byte[32];

            var ctx = Dtls12CryptoUtils.DeriveKeys(master, clientRandom, serverRandom);

            Assert.HasCount(48, ctx.MasterSecret);
            Assert.HasCount(16, ctx.ClientKey);
            Assert.HasCount(16, ctx.ServerKey);
            Assert.HasCount(4,  ctx.ClientIv);
            Assert.HasCount(4,  ctx.ServerIv);
        }

        [TestMethod]
        public void DeriveKeys_IsDeterministic()
        {
            var master       = new byte[48]; master[7] = 0x77;
            var clientRandom = new byte[32]; clientRandom[0] = 0x11;
            var serverRandom = new byte[32]; serverRandom[0] = 0x22;

            var ctx1 = Dtls12CryptoUtils.DeriveKeys(master, clientRandom, serverRandom);
            var ctx2 = Dtls12CryptoUtils.DeriveKeys(master, clientRandom, serverRandom);

            Assert.AreEqual(Convert.ToHexString(ctx1.ClientKey), Convert.ToHexString(ctx2.ClientKey));
            Assert.AreEqual(Convert.ToHexString(ctx1.ServerKey), Convert.ToHexString(ctx2.ServerKey));
            Assert.AreEqual(Convert.ToHexString(ctx1.ClientIv),  Convert.ToHexString(ctx2.ClientIv));
            Assert.AreEqual(Convert.ToHexString(ctx1.ServerIv),  Convert.ToHexString(ctx2.ServerIv));
        }

        [TestMethod]
        public void DeriveKeys_ClientAndServer_KeysAreDifferent()
        {
            var master       = new byte[48]; master[0] = 0xAB;
            var clientRandom = new byte[32]; clientRandom[0] = 0x01;
            var serverRandom = new byte[32]; serverRandom[0] = 0x02;

            var ctx = Dtls12CryptoUtils.DeriveKeys(master, clientRandom, serverRandom);

            Assert.AreNotEqual(Convert.ToHexString(ctx.ClientKey), Convert.ToHexString(ctx.ServerKey));
        }

        // ── VerifyData ────────────────────────────────────────────────────────

        [TestMethod]
        public void VerifyData_Is12Bytes_AndDeterministic()
        {
            var master = new byte[48]; master[3] = 0x55;
            var hash   = new byte[32]; hash[0] = 0xAB;

            byte[] v1 = Dtls12CryptoUtils.CalculateVerifyData(master, "client finished", hash);
            byte[] v2 = Dtls12CryptoUtils.CalculateVerifyData(master, "client finished", hash);

            Assert.HasCount(12, v1);
            Assert.AreEqual(Convert.ToHexString(v1), Convert.ToHexString(v2));
        }

        [TestMethod]
        public void VerifyData_ClientAndServer_DifferForSameInputs()
        {
            var master = new byte[48]; master[0] = 0x99;
            var hash   = new byte[32]; hash[0] = 0x55;

            byte[] clientVerify = Dtls12CryptoUtils.CalculateVerifyData(master, "client finished", hash);
            byte[] serverVerify = Dtls12CryptoUtils.CalculateVerifyData(master, "server finished", hash);

            Assert.AreNotEqual(Convert.ToHexString(clientVerify), Convert.ToHexString(serverVerify));
        }

        // ── Cookie ──────────────────────────────────────────────────────────

        [TestMethod]
        public void Cookie_SameInputsProduceSameOutput()
        {
            var ts = DateTime.UtcNow;
            byte[] c1 = Dtls12CryptoUtils.CreateCookie(ts, "127.0.0.1", 12345);
            byte[] c2 = Dtls12CryptoUtils.CreateCookie(ts, "127.0.0.1", 12345);
            Assert.AreEqual(Convert.ToHexString(c1), Convert.ToHexString(c2));
        }

        [TestMethod]
        public void Cookie_DifferentPorts_ProduceDifferentOutputs()
        {
            var ts = DateTime.UtcNow;
            byte[] c1 = Dtls12CryptoUtils.CreateCookie(ts, "127.0.0.1", 12345);
            byte[] c2 = Dtls12CryptoUtils.CreateCookie(ts, "127.0.0.1", 12346);
            Assert.AreNotEqual(Convert.ToHexString(c1), Convert.ToHexString(c2));
        }

        [TestMethod]
        public void Cookie_DifferentIps_ProduceDifferentOutputs()
        {
            var ts = DateTime.UtcNow;
            byte[] c1 = Dtls12CryptoUtils.CreateCookie(ts, "127.0.0.1", 12345);
            byte[] c2 = Dtls12CryptoUtils.CreateCookie(ts, "10.0.0.1",  12345);
            Assert.AreNotEqual(Convert.ToHexString(c1), Convert.ToHexString(c2));
        }

        [TestMethod]
        public void Cookie_ValidatePasses_ForCurrentTimestamp()
        {
            var ts    = DateTime.UtcNow;
            byte[] cookie = Dtls12CryptoUtils.CreateCookie(ts, "10.0.0.1", 54321);
            Assert.IsTrue(Dtls12CryptoUtils.ValidateCookie(ts, "10.0.0.1", 54321, cookie));
        }

        [TestMethod]
        public void Cookie_ValidateFails_ForWrongPort()
        {
            var ts    = DateTime.UtcNow;
            byte[] cookie = Dtls12CryptoUtils.CreateCookie(ts, "10.0.0.1", 54321);
            Assert.IsFalse(Dtls12CryptoUtils.ValidateCookie(ts, "10.0.0.1", 54322, cookie));
        }

        [TestMethod]
        public void Cookie_ValidateFails_ForWrongIp()
        {
            var ts    = DateTime.UtcNow;
            byte[] cookie = Dtls12CryptoUtils.CreateCookie(ts, "10.0.0.1", 54321);
            Assert.IsFalse(Dtls12CryptoUtils.ValidateCookie(ts, "10.0.0.2", 54321, cookie));
        }
    }
}
