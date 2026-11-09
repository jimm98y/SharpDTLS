using SharpDTLS.Protocol10;
using System;

namespace SharpDTLS.Tests
{
    [TestClass]
    public sealed class TestDtls10
    {
        // ── PRF ──────────────────────────────────────────────────────────────

        [TestMethod]
        public void Prf_IsDeterministic()
        {
            var secret = new byte[48];
            var seed   = new byte[32];
            seed[0] = 0x42;

            byte[] a = Tls10Prf.PRF(secret, "test label", seed, 48);
            byte[] b = Tls10Prf.PRF(secret, "test label", seed, 48);

            Assert.AreEqual(Convert.ToHexString(a), Convert.ToHexString(b));
        }

        [TestMethod]
        public void Prf_ProducesCorrectLength()
        {
            var secret = new byte[48];
            var seed   = new byte[32];

            byte[] output = Tls10Prf.PRF(secret, "key expansion", seed, 72);

            Assert.HasCount(72, output);
        }

        [TestMethod]
        public void Prf_ShorterOutputIsPrefixOfLonger()
        {
            var secret = new byte[48];
            var seed   = new byte[32];

            byte[] shorter = Tls10Prf.PRF(secret, "key expansion", seed, 20);
            byte[] longer  = Tls10Prf.PRF(secret, "key expansion", seed, 60);

            for (int i = 0; i < 20; i++)
                Assert.AreEqual(shorter[i], longer[i], $"Mismatch at byte {i}");
        }

        [TestMethod]
        public void Prf_Dtls10_DiffersFrom_Dtls12_ForSameInputs()
        {
            // TLS 1.0 uses P_MD5 XOR P_SHA1; TLS 1.2 uses P_SHA256 — must produce different output.
            var secret = new byte[48]; secret[0] = 0xAB;
            var seed   = new byte[32]; seed[0]   = 0xCD;

            byte[] prf10 = Tls10Prf.PRF(secret, "master secret", seed, 48);
            byte[] prf12 = SharpDTLS.Protocol12.Dtls12CryptoUtils.PRF(secret, "master secret", seed, 48);

            Assert.AreNotEqual(Convert.ToHexString(prf10), Convert.ToHexString(prf12));
        }

        // ── MasterSecret ──────────────────────────────────────────────────────

        [TestMethod]
        public void MasterSecret_Is48Bytes_AndDeterministic()
        {
            var preMaster    = new byte[32]; preMaster[0] = 0x01;
            var clientRandom = new byte[32]; clientRandom[0] = 0x02;
            var serverRandom = new byte[32]; serverRandom[0] = 0x03;

            byte[] ms1 = Tls10Prf.CalculateMasterSecret(preMaster, clientRandom, serverRandom);
            byte[] ms2 = Tls10Prf.CalculateMasterSecret(preMaster, clientRandom, serverRandom);

            Assert.HasCount(48, ms1);
            Assert.AreEqual(Convert.ToHexString(ms1), Convert.ToHexString(ms2));
        }

        // ── VerifyData ────────────────────────────────────────────────────────

        [TestMethod]
        public void VerifyData_Is12Bytes_AndDeterministic()
        {
            var master = new byte[48]; master[3] = 0x55;
            // TLS 1.0 transcript hash is MD5(16) || SHA1(20) = 36 bytes
            var hash   = new byte[36]; hash[0] = 0xAB;

            byte[] v1 = Tls10Prf.CalculateVerifyData(master, "client finished", hash);
            byte[] v2 = Tls10Prf.CalculateVerifyData(master, "client finished", hash);

            Assert.HasCount(12, v1);
            Assert.AreEqual(Convert.ToHexString(v1), Convert.ToHexString(v2));
        }

        [TestMethod]
        public void VerifyData_ClientAndServer_DifferForSameInputs()
        {
            var master = new byte[48]; master[0] = 0x99;
            var hash   = new byte[36]; hash[0] = 0x55;

            byte[] clientVerify = Tls10Prf.CalculateVerifyData(master, "client finished", hash);
            byte[] serverVerify = Tls10Prf.CalculateVerifyData(master, "server finished", hash);

            Assert.AreNotEqual(Convert.ToHexString(clientVerify), Convert.ToHexString(serverVerify));
        }
    }
}
