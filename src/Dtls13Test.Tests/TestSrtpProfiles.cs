using SharpDTLS;
using System.Linq;

namespace Dtls13Test.Tests
{
    /// <summary>DTLS-SRTP protection profiles of RFC 8269 (ARIA) and RFC 8723 (double AEAD) in both engines.</summary>
    [TestClass]
    public sealed class TestSrtpProfiles
    {
        [DataRow(12, DtlsSrtp.DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM)]
        [DataRow(12, DtlsSrtp.DOUBLE_AEAD_AES_256_GCM_AEAD_AES_256_GCM)]
        [DataRow(12, DtlsSrtp.SRTP_ARIA_128_CTR_HMAC_SHA1_80)]
        [DataRow(12, DtlsSrtp.SRTP_ARIA_256_CTR_HMAC_SHA1_32)]
        [DataRow(12, DtlsSrtp.SRTP_AEAD_ARIA_128_GCM)]
        [DataRow(12, DtlsSrtp.SRTP_AEAD_ARIA_256_GCM)]
        [DataRow(13, DtlsSrtp.DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM)]
        [DataRow(13, DtlsSrtp.DOUBLE_AEAD_AES_256_GCM_AEAD_AES_256_GCM)]
        [DataRow(13, DtlsSrtp.SRTP_ARIA_128_CTR_HMAC_SHA1_80)]
        [DataRow(13, DtlsSrtp.SRTP_ARIA_256_CTR_HMAC_SHA1_32)]
        [DataRow(13, DtlsSrtp.SRTP_AEAD_ARIA_128_GCM)]
        [DataRow(13, DtlsSrtp.SRTP_AEAD_ARIA_256_GCM)]
        [TestMethod]
        public void Profile_IsNegotiatedWithMatchingKeys(int version, ushort profile)
        {
            var r = EngineRun.Connect(version, new[] { profile });
            Assert.IsNull(r.Error, r.Error?.ToString());

            var server = r.ServerConnection();
            Assert.AreEqual(profile, r.Client.SelectedSrtpProtectionProfile);
            Assert.AreEqual(profile, server.SelectedSrtpProtectionProfile);

            var clientKeys = r.Client.GetSrtpKeys();
            var serverKeys = server.GetSrtpKeys();
            CollectionAssert.AreEqual(clientKeys.ClientWriteKey, serverKeys.ClientWriteKey);
            CollectionAssert.AreEqual(clientKeys.ServerWriteSalt, serverKeys.ServerWriteSalt);
        }

        [TestMethod]
        public void ServerPreference_PicksDoubleAeadFirst()
        {
            var r = EngineRun.Connect(13, new[] { DtlsSrtp.DOUBLE_AEAD_AES_256_GCM_AEAD_AES_256_GCM, DtlsSrtp.SRTP_AEAD_AES_256_GCM });
            Assert.IsNull(r.Error, r.Error?.ToString());
            Assert.AreEqual(DtlsSrtp.DOUBLE_AEAD_AES_256_GCM_AEAD_AES_256_GCM, r.Client.SelectedSrtpProtectionProfile);
        }

        [TestMethod]
        public void DoubleAead_KeepsInnerAndOuterKeyingMaterialApart()
        {
            // RFC 8723 §8.1: inner client key | inner server key | inner client salt | inner server salt | the same for the outer layer
            ushort profile = DtlsSrtp.DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM;
            Assert.AreEqual(2 * (32 + 24), DtlsSrtp.KeyingMaterialLength(profile));
            byte[] material = Enumerable.Range(0, 112).Select(i => (byte)i).ToArray();

            var keys = DtlsSrtp.Split(profile, material);

            byte[] Bytes(int innerOffset, int length) => Enumerable.Range(innerOffset, length).Concat(Enumerable.Range(56 + innerOffset, length)).Select(i => (byte)i).ToArray();
            CollectionAssert.AreEqual(Bytes(0, 16), keys.ClientWriteKey);
            CollectionAssert.AreEqual(Bytes(16, 16), keys.ServerWriteKey);
            CollectionAssert.AreEqual(Bytes(32, 12), keys.ClientWriteSalt);
            CollectionAssert.AreEqual(Bytes(44, 12), keys.ServerWriteSalt);
        }

        [TestMethod]
        public void Aria_UsesTheStandardLayout()
        {
            ushort profile = DtlsSrtp.SRTP_ARIA_256_CTR_HMAC_SHA1_80;
            byte[] material = Enumerable.Range(0, DtlsSrtp.KeyingMaterialLength(profile)).Select(i => (byte)i).ToArray();

            var keys = DtlsSrtp.Split(profile, material);

            CollectionAssert.AreEqual(material.Take(32).ToArray(), keys.ClientWriteKey);
            CollectionAssert.AreEqual(material.Skip(32).Take(32).ToArray(), keys.ServerWriteKey);
            CollectionAssert.AreEqual(material.Skip(64).Take(14).ToArray(), keys.ClientWriteSalt);
            CollectionAssert.AreEqual(material.Skip(78).Take(14).ToArray(), keys.ServerWriteSalt);
        }
    }
}
