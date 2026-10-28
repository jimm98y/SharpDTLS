using SharpDTLS.Protocol13;
using System;
using System.Linq;
using System.Runtime.Intrinsics;

namespace Dtls13Test.Tests
{
    /// <summary>AEGIS-128L and AEGIS-256 against the draft-irtf-cfrg-aegis-aead-08 Appendix A vectors.</summary>
    [TestClass]
    public sealed class TestAegis
    {
        private static byte[] Hex(string hex) => Convert.FromHexString(hex.Replace(" ", ""));
        private static Vector128<byte> V(string hex) => Vector128.Create(Hex(hex));

        [TestMethod]
        public void AesRound_HardwareAndSoftware()
        {
            var input = V("000102030405060708090a0b0c0d0e0f");
            var rk = V("101112131415161718191a1b1c1d1e1f");
            var expected = V("7a7b4e5638782546a8c0477a3b813f43");
            Assert.AreEqual(expected, Aegis.AesRound(input, rk));
            Assert.AreEqual(expected, Aegis.SoftwareAesRound(input, rk));

            // The fallback must agree with the AES instructions on arbitrary inputs, covering every S-box entry.
            var random = new Random(1);
            for (int i = 0; i < 256; i++)
            {
                byte[] a = new byte[16], b = new byte[16];
                random.NextBytes(a);
                random.NextBytes(b);
                a[0] = (byte)i;
                Assert.AreEqual(Aegis.AesRound(Vector128.Create(a), Vector128.Create(b)), Aegis.SoftwareAesRound(Vector128.Create(a), Vector128.Create(b)));
            }
        }

        [TestMethod]
        public void Update128L()
        {
            var s = new[]
            {
                V("9b7e60b24cc873ea894ecc07911049a3"), V("330be08f35300faa2ebf9a7b0d274658"),
                V("7bbd5bd2b049f7b9b515cf26fbe7756c"), V("c35a00f55ea86c3886ec5e928f87db18"),
                V("9ebccafce87cab446396c4334592c91f"), V("58d83e31f256371e60fc6bb257114601"),
                V("1639b56ea322c88568a176585bc915de"), V("640818ffb57dc0fbc2e72ae93457e39a"),
            };
            Aegis.Update128L(s, V("033e6975b94816879e42917650955aa0"), V("033e6975b94816879e42917650955aa0"));
            CollectionAssert.AreEqual(new[]
            {
                V("596ab773e4433ca0127c73f60536769d"), V("790394041a3d26ab697bde865014652d"),
                V("38cf49e4b65248acd533041b64dd0611"), V("16d8e58748f437bfff1797f780337cee"),
                V("69761320f7dd738b281cc9f335ac2f5a"), V("a21746bb193a569e331e1aa985d0d729"),
                V("09d714e6fcf9177a8ed1cde7e3d259a6"), V("61279ba73167f0ab76f0a11bf203bdff"),
            }, s);
        }

        [TestMethod]
        public void Update256()
        {
            var s = new[]
            {
                V("1fa1207ed76c86f2c4bb40e8b395b43e"), V("b44c375e6c1e1978db64bcd12e9e332f"),
                V("0dab84bfa9f0226432ff630f233d4e5b"), V("d7ef65c9b93e8ee60c75161407b066e7"),
                V("a760bb3da073fbd92bdc24734b1f56fb"), V("a828a18d6a964497ac6e7e53c5f55c73"),
            };
            Aegis.Update256(s, V("b165617ed04ab738afb2612c6d18a1ec"));
            CollectionAssert.AreEqual(new[]
            {
                V("e6bc643bae82dfa3d991b1b323839dcd"), V("648578232ba0f2f0a3677f617dc052c3"),
                V("ea788e0e572044a46059212dd007a789"), V("2f1498ae19b80da13fba698f088a8590"),
                V("a54c2ee95e8c2a2c3dae2ec743ae6b86"), V("a3240fceb68e32d5d114df1b5363ab67"),
            }, s);
        }

        private const string Key128 = "10010000000000000000000000000000";
        private const string Nonce128 = "10000200000000000000000000000000";
        private const string Key256 = "1001000000000000000000000000000000000000000000000000000000000000";
        private const string Nonce256 = "1000020000000000000000000000000000000000000000000000000000000000";

        // (ad, msg, ct, tag128, tag256) for test vectors 1-5.
        [DataRow(false, "", "00000000000000000000000000000000", "c1c0e58bd913006feba00f4b3cc3594e",
            "abe0ece80c24868a226a35d16bdae37a", "25835bfbb21632176cf03840687cb968cace4617af1bd0f7d064c639a5c79ee4")]
        [DataRow(false, "", "", "", "c2b879a67def9d74e6c14f708bbcc9b4", "1360dc9db8ae42455f6e5b6a9d488ea4f2184c4e12120249335c4ee84bafe25d")]
        [DataRow(false, "0001020304050607", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "79d94593d8c2119d7e8fd9b8fc77845c5c077a05b2528b6ac54b563aed8efe84",
            "cc6f3372f6aa1bb82388d695c3962d9a", "022cb796fe7e0ae1197525ff67e309484cfbab6528ddef89f17d74ef8ecd82b3")]
        [DataRow(false, "0001020304050607", "000102030405060708090a0b0c0d", "79d94593d8c2119d7e8fd9b8fc77",
            "5c04b3dba849b2701effbe32c7f0fab7", "86f1b80bfb463aba711d15405d094baf4a55a15dbfec81a76f35ed0b9c8b04ac")]
        [DataRow(false, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829",
            "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637",
            "b31052ad1cca4e291abcf2df3502e6bdb1bfd6db36798be3607b1f94d34478aa7ede7f7a990fec10",
            "7542a745733014f9474417b337399507", "b91e2947a33da8bee89b6794e647baf0fc835ff574aca3fc27c33be0db2aff98")]
        [DataRow(true, "", "00000000000000000000000000000000", "754fc3d8c973246dcc6d741412a4b236",
            "3fe91994768b332ed7f570a19ec5896e", "1181a1d18091082bf0266f66297d167d2e68b845f61a3b0527d31fc7b7b89f13")]
        [DataRow(true, "", "", "", "e3def978a0f054afd1e761d7553afba3", "6a348c930adbd654896e1666aad67de989ea75ebaa2b82fb588977b1ffec864a")]
        [DataRow(true, "0001020304050607", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "f373079ed84b2709faee373584585d60accd191db310ef5d8b11833df9dec711",
            "8d86f91ee606e9ff26a01b64ccbdd91d", "b7d28d0c3c0ebd409fd22b44160503073a547412da0854bfb9723020dab8da1a")]
        [DataRow(true, "0001020304050607", "000102030405060708090a0b0c0d", "f373079ed84b2709faee37358458",
            "c60b9c2d33ceb058f96e6dd03c215652", "8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2d9")]
        [DataRow(true, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829",
            "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637",
            "57754a7d09963e7c787583a2e7b859bb24fa1e04d49fd550b2511a358e3bca252a9b1b8b30cc4a67",
            "ab8a7d53fd0e98d727accca94925e128", "a3aca270c006094d71c20e6910b5161c0826df233d08919a566ec2c05990f734")]
        [TestMethod]
        public void Vectors(bool aegis256, string ad, string msg, string ct, string tag128, string tag256)
        {
            byte[] key = Hex(aegis256 ? Key256 : Key128), nonce = Hex(aegis256 ? Nonce256 : Nonce128);
            foreach (var (tagLength, tag) in new[] { (16, tag128), (32, tag256) })
            {
                byte[] expected = Hex(ct + tag);
                byte[] sealedData = aegis256
                    ? Aegis.Encrypt256(key, nonce, Hex(ad), Hex(msg), tagLength)
                    : Aegis.Encrypt128L(key, nonce, Hex(ad), Hex(msg), tagLength);
                CollectionAssert.AreEqual(expected, sealedData, $"tag length {tagLength}");

                byte[] opened = aegis256
                    ? Aegis.Decrypt256(key, nonce, Hex(ad), expected, tagLength)
                    : Aegis.Decrypt128L(key, nonce, Hex(ad), expected, tagLength);
                CollectionAssert.AreEqual(Hex(msg), opened, $"tag length {tagLength}");
            }
        }

        // Vectors 6-9: swapped key and nonce, altered ciphertext, altered ad, altered tag.
        [DataRow(false, true, "0001020304050607", "79d94593d8c2119d7e8fd9b8fc77", "5c04b3dba849b2701effbe32c7f0fab7")]
        [DataRow(false, false, "0001020304050607", "79d94593d8c2119d7e8fd9b8fc78", "5c04b3dba849b2701effbe32c7f0fab7")]
        [DataRow(false, false, "0001020304050608", "79d94593d8c2119d7e8fd9b8fc77", "5c04b3dba849b2701effbe32c7f0fab7")]
        [DataRow(false, false, "0001020304050607", "79d94593d8c2119d7e8fd9b8fc77", "6c04b3dba849b2701effbe32c7f0fab8")]
        [DataRow(true, true, "0001020304050607", "f373079ed84b2709faee37358458", "c60b9c2d33ceb058f96e6dd03c215652")]
        [DataRow(true, false, "0001020304050607", "f373079ed84b2709faee37358459", "c60b9c2d33ceb058f96e6dd03c215652")]
        [DataRow(true, false, "0001020304050608", "f373079ed84b2709faee37358458", "c60b9c2d33ceb058f96e6dd03c215652")]
        [DataRow(true, false, "0001020304050607", "f373079ed84b2709faee37358458", "c60b9c2d33ceb058f96e6dd03c215653")]
        [TestMethod]
        public void NegativeVectors_FailVerification(bool aegis256, bool swapKeyAndNonce, string ad, string ct, string tag)
        {
            byte[] key = Hex(aegis256 ? Key256 : Key128), nonce = Hex(aegis256 ? Nonce256 : Nonce128);
            if (swapKeyAndNonce)
                (key, nonce) = (nonce, key);
            byte[] input = Hex(ct + tag);
            Assert.IsNull(aegis256 ? Aegis.Decrypt256(key, nonce, Hex(ad), input) : Aegis.Decrypt128L(key, nonce, Hex(ad), input));
        }
    }
}
