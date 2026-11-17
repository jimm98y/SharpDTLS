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

namespace SharpDTLS
{
    /// <summary>
    /// One ephemeral key of a key exchange group (RFC 8446 §4.2.7): (EC)DHE, X25519, X448, FFDHE, or the decapsulation key
    /// of ML-KEM. Hybrid groups are made of two.
    /// </summary>
    public interface ITlsKeyShare
    {
        /// <summary>
        /// Our public value as TLS sends it: an uncompressed EC point, an X25519 or X448 key, an FFDHE value as long as
        /// the prime, or an ML-KEM encapsulation key.
        /// </summary>
        byte[] PublicKey { get; }

        /// <summary>
        /// The shared secret with the peer's public value (of ML-KEM, its ciphertext): an EC x-coordinate, the raw
        /// X25519/X448 result or the FFDHE secret, each as long as the field. Throws a <see cref="System.Security.Cryptography.CryptographicException"/>
        /// for an invalid peer value (off the curve, the wrong length, a small-order point).
        /// </summary>
        byte[] Agree(byte[] peerPublicKey);
    }

    /// <summary>A key share of a public value and an agreement.</summary>
    internal sealed class KeyShare : ITlsKeyShare
    {
        private readonly Func<byte[], byte[]> _agree;

        public KeyShare(byte[] publicKey, Func<byte[], byte[]> agree)
        {
            PublicKey = publicKey;
            _agree = agree;
        }

        public byte[] PublicKey { get; }

        public byte[] Agree(byte[] peerPublicKey) => _agree(peerPublicKey);
    }
}
