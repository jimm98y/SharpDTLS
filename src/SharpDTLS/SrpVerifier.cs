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

using Org.BouncyCastle.Crypto.Agreement.Srp;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using SharpDTLS.Protocol12;
using System;
using System.Collections.Generic;

namespace SharpDTLS
{
    /// <summary>
    /// An SRP password verifier as a server stores it (RFC 5054 §2.4): v = g^x mod N with
    /// x = SHA1(s | SHA1(I | ":" | P)).
    /// </summary>
    public sealed class SrpVerifier
    {
        public SrpVerifier(Srp6GroupParameters group, byte[] salt, BigInteger verifier)
        {
            if (salt == null || salt.Length is 0 or > 255)
                throw new ArgumentException("The salt must be 1 to 255 bytes.", nameof(salt));
            Group = group ?? throw new ArgumentNullException(nameof(group));
            Salt = salt;
            Verifier = verifier ?? throw new ArgumentNullException(nameof(verifier));
        }

        public Srp6GroupParameters Group { get; }
        public byte[] Salt { get; }
        public BigInteger Verifier { get; }

        /// <summary>The RFC 5054 Appendix A groups, which clients accept.</summary>
        public static IReadOnlyList<Srp6GroupParameters> StandardGroups { get; } = new[]
        {
            Srp6StandardGroups.rfc5054_1024, Srp6StandardGroups.rfc5054_1536, Srp6StandardGroups.rfc5054_2048,
            Srp6StandardGroups.rfc5054_3072, Srp6StandardGroups.rfc5054_4096, Srp6StandardGroups.rfc5054_6144,
            Srp6StandardGroups.rfc5054_8192,
        };

        /// <summary>Creates a verifier with a random 16-byte salt, on the 2048-bit group unless another is given.</summary>
        public static SrpVerifier Create(byte[] identity, byte[] password, Srp6GroupParameters group = null)
        {
            group ??= Srp6StandardGroups.rfc5054_2048;
            byte[] salt = Dtls12CryptoUtils.GenerateRandom(16);
            var generator = new Srp6VerifierGenerator();
            generator.Init(group, new Sha1Digest());
            return new SrpVerifier(group, salt, generator.GenerateVerifier(salt, identity, password));
        }
    }
}
