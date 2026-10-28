using SharpDTLS.Protocol12;
using System;

namespace Dtls13Test.Tests
{
    /// <summary>SIV-AES against the RFC 5297 Appendix A vectors.</summary>
    [TestClass]
    public sealed class TestAesSiv
    {
        private static byte[] Hex(string hex) => Convert.FromHexString(hex.Replace(" ", ""));

        [TestMethod]
        public void DeterministicExample_A1()
        {
            byte[] key = Hex("fffefdfc fbfaf9f8 f7f6f5f4 f3f2f1f0 f0f1f2f3 f4f5f6f7 f8f9fafb fcfdfeff");
            byte[] ad = Hex("10111213 14151617 18191a1b 1c1d1e1f 20212223 24252627");
            byte[] plaintext = Hex("11223344 55667788 99aabbcc ddee");
            byte[] expected = Hex("85632d07 c6e8f37f 950acd32 0a2ecc93 40c02b96 90c4dc04 daef7f6a fe5c");

            CollectionAssert.AreEqual(expected, AesSiv.Encrypt(key, plaintext, ad));
            CollectionAssert.AreEqual(plaintext, AesSiv.Decrypt(key, expected, ad));
        }

        [TestMethod]
        public void NonceBasedExample_A2()
        {
            byte[] key = Hex("7f7e7d7c 7b7a7978 77767574 73727170 40414243 44454647 48494a4b 4c4d4e4f");
            byte[] ad1 = Hex("00112233 44556677 8899aabb ccddeeff deaddada deaddada ffeeddcc bbaa9988 77665544 33221100");
            byte[] ad2 = Hex("10203040 50607080 90a0");
            byte[] nonce = Hex("09f91102 9d74e35b d84156c5 635688c0");
            byte[] plaintext = Hex("74686973 20697320 736f6d65 20706c61 696e7465 78742074 6f20656e 63727970 74207573 696e6720 5349562d 414553");
            byte[] expected = Hex("7bdb6e3b 432667eb 06f4d14b ff2fbd0f cb900f2f ddbe4043 26601965 c889bf17 "
                                + "dba77ceb 094fa663 b7a3f748 ba8af829 ea64ad54 4a272e9c 485b62a3 fd5c0d");

            CollectionAssert.AreEqual(expected, AesSiv.Encrypt(key, plaintext, ad1, ad2, nonce));
            CollectionAssert.AreEqual(plaintext, AesSiv.Decrypt(key, expected, ad1, ad2, nonce));
        }

        [TestMethod]
        public void TamperedCiphertext_FailsAuthentication()
        {
            byte[] key = new byte[32];
            byte[] z = AesSiv.Encrypt(key, new byte[40]);
            z[^1] ^= 1;
            Assert.IsNull(AesSiv.Decrypt(key, z));
        }
    }
}
