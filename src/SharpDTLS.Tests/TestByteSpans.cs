using System;

namespace SharpDTLS.Tests
{
    /// <summary>The record path's byte span operations against plain loops, at every length the vectors split.</summary>
    [TestClass]
    public sealed class TestByteSpans
    {
        [TestMethod]
        public void Xor_IsTheBytewiseXor_InPlaceToo()
        {
            var random = new Random(7);
            for (int length = 0; length <= 100; length++)
            {
                byte[] a = new byte[length], b = new byte[length];
                random.NextBytes(a);
                random.NextBytes(b);
                byte[] expected = new byte[length];
                for (int i = 0; i < length; i++)
                    expected[i] = (byte)(a[i] ^ b[i]);

                byte[] result = new byte[length];
                ByteSpans.Xor(a, b, result);
                CollectionAssert.AreEqual(expected, result, $"length {length}");

                ByteSpans.Xor(a, b, a);
                CollectionAssert.AreEqual(expected, a, $"in place, length {length}");
            }
        }

        [TestMethod]
        public void Xor_RefusesShortInputs()
            => Assert.ThrowsExactly<ArgumentException>(() => ByteSpans.Xor(new byte[3], new byte[4], new byte[4]));

        [TestMethod]
        public void WithoutTrailingZeros_IsTheLengthUpToTheLastNonZeroByte()
        {
            for (int length = 0; length <= 70; length++)
            {
                for (int last = -1; last < length; last++)
                {
                    byte[] data = new byte[length];
                    if (last >= 0)
                        data[last] = 0x17;
                    Assert.AreEqual(last + 1, ByteSpans.WithoutTrailingZeros(data), $"length {length}, last {last}");
                }
            }
        }

        [TestMethod]
        public void IsAllZero()
        {
            Assert.IsTrue(ByteSpans.IsAllZero(new byte[32]));
            Assert.IsTrue(ByteSpans.IsAllZero(Array.Empty<byte>()));
            for (int i = 0; i < 56; i++)
            {
                byte[] data = new byte[56];
                data[i] = 1;
                Assert.IsFalse(ByteSpans.IsAllZero(data), $"byte {i}");
            }
        }

        [TestMethod]
        public void XorNonce_XorsTheSequenceNumberIntoTheLast8Bytes()
        {
            byte[] iv = Convert.FromHexString("5d313eb2671276ee13000b30");
            byte[] nonce = new byte[12];
            ByteSpans.XorNonce(iv, 0x0102030405060708UL, nonce);
            CollectionAssert.AreEqual(Convert.FromHexString("5d313eb2" + "6610" + "75ea" + "16" + "06" + "0c" + "38"), nonce);
        }
    }
}
