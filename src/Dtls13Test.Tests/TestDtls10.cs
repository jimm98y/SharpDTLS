using SharpDTLS.DTLS10;
using Dtls10Messages = SharpDTLS.DTLS10.Messages;
using System;
using System.Collections.Generic;

namespace Dtls13Test.Tests
{
    [TestClass]
    public sealed class TestDtls10
    {
        // ── ClientHello ──────────────────────────────────────────────────────

        [TestMethod]
        public void ClientHello_RoundTrip()
        {
            var random = new byte[32];
            random[0] = 0xAB; random[31] = 0xCD;

            var ch = new Dtls10Messages.ClientHelloDatagram
            {
                ClientRandom          = random,
                CipherSuites          = new List<ushort> { 0xC013, 0xC014 },
                RecordSequenceNumber  = 5,
                MessageSequenceNumber = 2,
            };
            byte[] bytes = ch.ToBytes();

            var ch2 = new Dtls10Messages.ClientHelloDatagram();
            ch2.FromBytes(bytes);

            Assert.AreEqual(Convert.ToHexString(random), Convert.ToHexString(ch2.ClientRandom));
            Assert.HasCount(2,      ch2.CipherSuites);
            Assert.AreEqual(0xC013, ch2.CipherSuites[0]);
            Assert.AreEqual(0xC014, ch2.CipherSuites[1]);
            Assert.AreEqual(5,      ch2.RecordSequenceNumber);
            Assert.AreEqual(2,      ch2.MessageSequenceNumber);
            Assert.HasCount(0,      ch2.Cookie);
            Assert.AreEqual(Convert.ToHexString(bytes), Convert.ToHexString(ch2.ToBytes()));
        }

        [TestMethod]
        public void ClientHello_WithCookie_RoundTrip()
        {
            var random = new byte[32];
            var cookie = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE };

            var ch = new Dtls10Messages.ClientHelloDatagram
            {
                ClientRandom = random,
                Cookie       = cookie,
                CipherSuites = new List<ushort> { 0xC013 },
            };
            byte[] bytes = ch.ToBytes();

            var ch2 = new Dtls10Messages.ClientHelloDatagram();
            ch2.FromBytes(bytes);

            Assert.AreEqual(Convert.ToHexString(cookie), Convert.ToHexString(ch2.Cookie));
            Assert.HasCount(1,      ch2.CipherSuites);
            Assert.AreEqual(0xC013, ch2.CipherSuites[0]);
            Assert.AreEqual(Convert.ToHexString(bytes), Convert.ToHexString(ch2.ToBytes()));
        }

        [TestMethod]
        public void ClientHello_VersionBytes_AreDtls10()
        {
            var ch = new Dtls10Messages.ClientHelloDatagram { ClientRandom = new byte[32] };
            byte[] bytes = ch.ToBytes();
            // Record version at offset 1-2 must be 0xFEFF (DTLS 1.0)
            Assert.AreEqual(0xFE, bytes[1]);
            Assert.AreEqual(0xFF, bytes[2]);
            // client_version at offset 25-26 must also be 0xFEFF
            Assert.AreEqual(0xFE, bytes[25]);
            Assert.AreEqual(0xFF, bytes[26]);
        }

        [TestMethod]
        public void ClientHello_WithDefaultExtensions_RoundTrip()
        {
            var ch = new Dtls10Messages.ClientHelloDatagram(includeSrtp: true);
            ch.ClientRandom = new byte[32];
            byte[] bytes = ch.ToBytes();

            var ch2 = new Dtls10Messages.ClientHelloDatagram();
            ch2.FromBytes(bytes);

            Assert.AreEqual(Convert.ToHexString(bytes), Convert.ToHexString(ch2.ToBytes()));
        }

        // ── ServerHello ──────────────────────────────────────────────────────

        [TestMethod]
        public void ServerHello_RoundTrip()
        {
            var random = new byte[32];
            random[0] = 0x33; random[31] = 0x44;

            var sh = new Dtls10Messages.ServerHelloDatagram(0xC013, random)
            {
                RecordSequenceNumber  = 4,
                MessageSequenceNumber = 2,
            };
            byte[] bytes = sh.ToBytes();

            var sh2 = new Dtls10Messages.ServerHelloDatagram();
            sh2.FromBytes(bytes);

            Assert.AreEqual(Convert.ToHexString(random), Convert.ToHexString(sh2.ServerRandom));
            Assert.AreEqual(0xC013, sh2.SelectedCipherSuite);
            Assert.AreEqual(4,      sh2.RecordSequenceNumber);
            Assert.AreEqual(2,      sh2.MessageSequenceNumber);
            Assert.AreEqual(Convert.ToHexString(bytes), Convert.ToHexString(sh2.ToBytes()));
        }

        [TestMethod]
        public void ServerHello_VersionBytes_AreDtls10()
        {
            var sh = new Dtls10Messages.ServerHelloDatagram(0xC013, new byte[32]);
            byte[] bytes = sh.ToBytes();
            // Record version at offset 1-2 must be 0xFEFF (DTLS 1.0)
            Assert.AreEqual(0xFE, bytes[1]);
            Assert.AreEqual(0xFF, bytes[2]);
            // server_version at offset 25-26 must also be 0xFEFF
            Assert.AreEqual(0xFE, bytes[25]);
            Assert.AreEqual(0xFF, bytes[26]);
        }

        [TestMethod]
        public void ServerHello_WithSrtp_RoundTrip()
        {
            var sh = new Dtls10Messages.ServerHelloDatagram(0xC013, new byte[32], includeSrtp: true, srtpProfile: 0x0001);
            byte[] bytes = sh.ToBytes();

            var sh2 = new Dtls10Messages.ServerHelloDatagram();
            sh2.FromBytes(bytes);

            Assert.AreEqual(0xC013, sh2.SelectedCipherSuite);
            Assert.AreEqual(Convert.ToHexString(bytes), Convert.ToHexString(sh2.ToBytes()));
        }

        // ── HelloVerifyRequest ────────────────────────────────────────────────

        [TestMethod]
        public void HelloVerifyRequest_RoundTrip()
        {
            var cookie = new byte[] { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
            var hvr = new Dtls10Messages.HelloVerifyRequestDatagram(cookie) { RecordSequenceNumber = 2 };
            byte[] bytes = hvr.ToBytes();

            var hvr2 = new Dtls10Messages.HelloVerifyRequestDatagram();
            hvr2.FromBytes(bytes);

            Assert.AreEqual(Convert.ToHexString(cookie), Convert.ToHexString(hvr2.Cookie));
            Assert.AreEqual(2, hvr2.RecordSequenceNumber);
            Assert.AreEqual(Convert.ToHexString(bytes), Convert.ToHexString(hvr2.ToBytes()));
        }

        [TestMethod]
        public void HelloVerifyRequest_VersionBytes_AreDtls10()
        {
            var hvr = new Dtls10Messages.HelloVerifyRequestDatagram(new byte[] { 0x01 });
            byte[] bytes = hvr.ToBytes();
            // Record version at offset 1-2 must be 0xFEFF (DTLS 1.0)
            Assert.AreEqual(0xFE, bytes[1]);
            Assert.AreEqual(0xFF, bytes[2]);
            // server_version field at offset 25-26 must also be 0xFEFF
            Assert.AreEqual(0xFE, bytes[25]);
            Assert.AreEqual(0xFF, bytes[26]);
        }

        // ── PRF ──────────────────────────────────────────────────────────────

        [TestMethod]
        public void Prf_IsDeterministic()
        {
            var secret = new byte[48];
            var seed   = new byte[32];
            seed[0] = 0x42;

            byte[] a = Dtls10CryptoUtils.PRF(secret, "test label", seed, 48);
            byte[] b = Dtls10CryptoUtils.PRF(secret, "test label", seed, 48);

            Assert.AreEqual(Convert.ToHexString(a), Convert.ToHexString(b));
        }

        [TestMethod]
        public void Prf_ProducesCorrectLength()
        {
            var secret = new byte[48];
            var seed   = new byte[32];

            byte[] output = Dtls10CryptoUtils.PRF(secret, "key expansion", seed, 72);

            Assert.HasCount(72, output);
        }

        [TestMethod]
        public void Prf_ShorterOutputIsPrefixOfLonger()
        {
            var secret = new byte[48];
            var seed   = new byte[32];

            byte[] shorter = Dtls10CryptoUtils.PRF(secret, "key expansion", seed, 20);
            byte[] longer  = Dtls10CryptoUtils.PRF(secret, "key expansion", seed, 60);

            for (int i = 0; i < 20; i++)
                Assert.AreEqual(shorter[i], longer[i], $"Mismatch at byte {i}");
        }

        [TestMethod]
        public void Prf_Dtls10_DiffersFrom_Dtls12_ForSameInputs()
        {
            // TLS 1.0 uses P_MD5 XOR P_SHA1; TLS 1.2 uses P_SHA256 — must produce different output.
            var secret = new byte[48]; secret[0] = 0xAB;
            var seed   = new byte[32]; seed[0]   = 0xCD;

            byte[] prf10 = Dtls10CryptoUtils.PRF(secret, "master secret", seed, 48);
            byte[] prf12 = SharpDTLS.DTLS12.Dtls12CryptoUtils.PRF(secret, "master secret", seed, 48);

            Assert.AreNotEqual(Convert.ToHexString(prf10), Convert.ToHexString(prf12));
        }

        // ── MasterSecret / DeriveKeys ─────────────────────────────────────────

        [TestMethod]
        public void MasterSecret_Is48Bytes_AndDeterministic()
        {
            var preMaster    = new byte[32]; preMaster[0] = 0x01;
            var clientRandom = new byte[32]; clientRandom[0] = 0x02;
            var serverRandom = new byte[32]; serverRandom[0] = 0x03;

            byte[] ms1 = Dtls10CryptoUtils.CalculateMasterSecret(preMaster, clientRandom, serverRandom);
            byte[] ms2 = Dtls10CryptoUtils.CalculateMasterSecret(preMaster, clientRandom, serverRandom);

            Assert.HasCount(48, ms1);
            Assert.AreEqual(Convert.ToHexString(ms1), Convert.ToHexString(ms2));
        }

        [TestMethod]
        public void DeriveKeys_ProducesCorrectLengths()
        {
            var master       = new byte[48]; master[0] = 0x55;
            var clientRandom = new byte[32];
            var serverRandom = new byte[32];

            var ctx = Dtls10CryptoUtils.DeriveKeys(master, clientRandom, serverRandom);

            Assert.HasCount(48, ctx.MasterSecret);
            Assert.HasCount(20, ctx.ClientMacKey);
            Assert.HasCount(20, ctx.ServerMacKey);
            Assert.HasCount(16, ctx.ClientKey);
            Assert.HasCount(16, ctx.ServerKey);
        }

        [TestMethod]
        public void DeriveKeys_IsDeterministic()
        {
            var master       = new byte[48]; master[7] = 0x77;
            var clientRandom = new byte[32]; clientRandom[0] = 0x11;
            var serverRandom = new byte[32]; serverRandom[0] = 0x22;

            var ctx1 = Dtls10CryptoUtils.DeriveKeys(master, clientRandom, serverRandom);
            var ctx2 = Dtls10CryptoUtils.DeriveKeys(master, clientRandom, serverRandom);

            Assert.AreEqual(Convert.ToHexString(ctx1.ClientMacKey), Convert.ToHexString(ctx2.ClientMacKey));
            Assert.AreEqual(Convert.ToHexString(ctx1.ServerMacKey), Convert.ToHexString(ctx2.ServerMacKey));
            Assert.AreEqual(Convert.ToHexString(ctx1.ClientKey),    Convert.ToHexString(ctx2.ClientKey));
            Assert.AreEqual(Convert.ToHexString(ctx1.ServerKey),    Convert.ToHexString(ctx2.ServerKey));
        }

        [TestMethod]
        public void DeriveKeys_ClientAndServer_KeysAreDifferent()
        {
            var master       = new byte[48]; master[0] = 0xAB;
            var clientRandom = new byte[32]; clientRandom[0] = 0x01;
            var serverRandom = new byte[32]; serverRandom[0] = 0x02;

            var ctx = Dtls10CryptoUtils.DeriveKeys(master, clientRandom, serverRandom);

            Assert.AreNotEqual(Convert.ToHexString(ctx.ClientKey),    Convert.ToHexString(ctx.ServerKey));
            Assert.AreNotEqual(Convert.ToHexString(ctx.ClientMacKey), Convert.ToHexString(ctx.ServerMacKey));
        }

        // ── VerifyData ────────────────────────────────────────────────────────

        [TestMethod]
        public void VerifyData_Is12Bytes_AndDeterministic()
        {
            var master = new byte[48]; master[3] = 0x55;
            // TLS 1.0 transcript hash is MD5(16) || SHA1(20) = 36 bytes
            var hash   = new byte[36]; hash[0] = 0xAB;

            byte[] v1 = Dtls10CryptoUtils.CalculateVerifyData(master, "client finished", hash);
            byte[] v2 = Dtls10CryptoUtils.CalculateVerifyData(master, "client finished", hash);

            Assert.HasCount(12, v1);
            Assert.AreEqual(Convert.ToHexString(v1), Convert.ToHexString(v2));
        }

        [TestMethod]
        public void VerifyData_ClientAndServer_DifferForSameInputs()
        {
            var master = new byte[48]; master[0] = 0x99;
            var hash   = new byte[36]; hash[0] = 0x55;

            byte[] clientVerify = Dtls10CryptoUtils.CalculateVerifyData(master, "client finished", hash);
            byte[] serverVerify = Dtls10CryptoUtils.CalculateVerifyData(master, "server finished", hash);

            Assert.AreNotEqual(Convert.ToHexString(clientVerify), Convert.ToHexString(serverVerify));
        }

        // ── Cookie ──────────────────────────────────────────────────────────

        [TestMethod]
        public void Cookie_SameInputsProduceSameOutput()
        {
            var ts = DateTime.UtcNow;
            byte[] c1 = Dtls10CryptoUtils.CreateCookie(ts, "127.0.0.1", 12345);
            byte[] c2 = Dtls10CryptoUtils.CreateCookie(ts, "127.0.0.1", 12345);
            Assert.AreEqual(Convert.ToHexString(c1), Convert.ToHexString(c2));
        }

        [TestMethod]
        public void Cookie_DifferentPorts_ProduceDifferentOutputs()
        {
            var ts = DateTime.UtcNow;
            byte[] c1 = Dtls10CryptoUtils.CreateCookie(ts, "127.0.0.1", 12345);
            byte[] c2 = Dtls10CryptoUtils.CreateCookie(ts, "127.0.0.1", 12346);
            Assert.AreNotEqual(Convert.ToHexString(c1), Convert.ToHexString(c2));
        }

        [TestMethod]
        public void Cookie_DifferentIps_ProduceDifferentOutputs()
        {
            var ts = DateTime.UtcNow;
            byte[] c1 = Dtls10CryptoUtils.CreateCookie(ts, "127.0.0.1", 12345);
            byte[] c2 = Dtls10CryptoUtils.CreateCookie(ts, "10.0.0.1",  12345);
            Assert.AreNotEqual(Convert.ToHexString(c1), Convert.ToHexString(c2));
        }

        [TestMethod]
        public void Cookie_ValidatePasses_ForCurrentTimestamp()
        {
            var ts    = DateTime.UtcNow;
            byte[] cookie = Dtls10CryptoUtils.CreateCookie(ts, "10.0.0.1", 54321);
            Assert.IsTrue(Dtls10CryptoUtils.ValidateCookie(ts, "10.0.0.1", 54321, cookie));
        }

        [TestMethod]
        public void Cookie_ValidateFails_ForWrongPort()
        {
            var ts    = DateTime.UtcNow;
            byte[] cookie = Dtls10CryptoUtils.CreateCookie(ts, "10.0.0.1", 54321);
            Assert.IsFalse(Dtls10CryptoUtils.ValidateCookie(ts, "10.0.0.1", 54322, cookie));
        }

        [TestMethod]
        public void Cookie_ValidateFails_ForWrongIp()
        {
            var ts    = DateTime.UtcNow;
            byte[] cookie = Dtls10CryptoUtils.CreateCookie(ts, "10.0.0.1", 54321);
            Assert.IsFalse(Dtls10CryptoUtils.ValidateCookie(ts, "10.0.0.2", 54321, cookie));
        }
    }
}
