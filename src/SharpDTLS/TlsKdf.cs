// SharpDTLS
// Copyright (C) 2026 Lukas Volf
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

using System;
using System.Collections.Generic;

namespace SharpDTLS
{
    /// <summary>Hashes, HMACs, the TLS PRF's P_hash and HKDF (RFC 5869) of an <see cref="ITlsCrypto"/>'s primitives.</summary>
    internal static class TlsKdf
    {
        public static byte[] Hash(ITlsCrypto crypto, TlsHashAlgorithm algorithm, byte[] data) => Hash(crypto, algorithm, new[] { data });

        public static byte[] Hash(ITlsCrypto crypto, TlsHashAlgorithm algorithm, IEnumerable<byte[]> parts)
        {
            var hash = crypto.CreateHash(algorithm);
            try
            {
                foreach (byte[] part in parts)
                    hash.Append(part);
                byte[] result = new byte[hash.HashLength];
                hash.Finish(result);
                return result;
            }
            finally
            {
                (hash as IDisposable)?.Dispose();
            }
        }

        public static byte[] Hmac(ITlsCrypto crypto, TlsHashAlgorithm algorithm, byte[] key, byte[] data)
        {
            var hmac = crypto.CreateHmac(algorithm, key);
            try
            {
                hmac.Append(data);
                byte[] result = new byte[hmac.HashLength];
                hmac.Finish(result);
                return result;
            }
            finally
            {
                (hmac as IDisposable)?.Dispose();
            }
        }

        /// <summary>P_hash(secret, seed) of RFC 5246 §5, <paramref name="length"/> bytes.</summary>
        public static byte[] PHash(ITlsCrypto crypto, TlsHashAlgorithm algorithm, byte[] secret, byte[] seed, int length)
        {
            var hmac = crypto.CreateHmac(algorithm, secret);
            try
            {
                byte[] result = new byte[length];
                byte[] a = new byte[hmac.HashLength];
                byte[] block = new byte[hmac.HashLength];
                hmac.Append(seed);
                hmac.Finish(a); // A(1)
                for (int offset = 0; offset < length; offset += block.Length)
                {
                    hmac.Append(a);
                    hmac.Append(seed);
                    hmac.Finish(block);
                    block.AsSpan(0, Math.Min(block.Length, length - offset)).CopyTo(result.AsSpan(offset));
                    hmac.Append(a);
                    hmac.Finish(a); // A(i+1)
                }
                return result;
            }
            finally
            {
                (hmac as IDisposable)?.Dispose();
            }
        }

        /// <summary>HKDF-Extract(salt, IKM) = HMAC(salt, IKM).</summary>
        public static byte[] HkdfExtract(ITlsCrypto crypto, TlsHashAlgorithm algorithm, byte[] salt, byte[] ikm) => Hmac(crypto, algorithm, salt, ikm);

        /// <summary>HKDF-Expand(PRK, info, L): T(i) = HMAC(PRK, T(i-1) || info || i).</summary>
        public static byte[] HkdfExpand(ITlsCrypto crypto, TlsHashAlgorithm algorithm, byte[] prk, byte[] info, int length)
        {
            var hmac = crypto.CreateHmac(algorithm, prk);
            try
            {
                int hashLength = hmac.HashLength;
                if (length > 255 * hashLength)
                    throw new ArgumentOutOfRangeException(nameof(length));
                byte[] result = new byte[length];
                byte[] t = new byte[hashLength];
                byte[] counter = new byte[1];
                for (int i = 0, offset = 0; offset < length; i++, offset += hashLength)
                {
                    if (i > 0)
                        hmac.Append(t);
                    hmac.Append(info);
                    counter[0] = (byte)(i + 1);
                    hmac.Append(counter);
                    hmac.Finish(t);
                    t.AsSpan(0, Math.Min(hashLength, length - offset)).CopyTo(result.AsSpan(offset));
                }
                return result;
            }
            finally
            {
                (hmac as IDisposable)?.Dispose();
            }
        }
    }
}
