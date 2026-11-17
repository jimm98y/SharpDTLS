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
using Org.BouncyCastle.Utilities;
using SharpDTLS.Protocol12;
using System;
using System.Collections.Generic;
using System.Linq;

namespace SharpDTLS
{
    /// <summary>An SRP group (RFC 5054 Appendix A): the prime N and the generator g, as unsigned big-endian bytes.</summary>
    public sealed class SrpGroup
    {
        public SrpGroup(byte[] n, byte[] g)
            : this(new Srp6GroupParameters(new BigInteger(1, n ?? throw new ArgumentNullException(nameof(n))),
                new BigInteger(1, g ?? throw new ArgumentNullException(nameof(g)))))
        {
        }

        private SrpGroup(Srp6GroupParameters group)
        {
            N = BigIntegers.AsUnsignedByteArray(group.N);
            G = BigIntegers.AsUnsignedByteArray(group.G);
            Bc = group;
        }

        public byte[] N { get; }
        public byte[] G { get; }

        internal Srp6GroupParameters Bc { get; }

        internal static SrpGroup Of(Srp6GroupParameters group) => new SrpGroup(group);
    }

    /// <summary>
    /// An SRP password verifier as a server stores it (RFC 5054 §2.4): v = g^x mod N with
    /// x = SHA1(s | SHA1(I | ":" | P)).
    /// </summary>
    public sealed class SrpVerifier
    {
        /// <param name="verifier">v, as unsigned big-endian bytes.</param>
        public SrpVerifier(SrpGroup group, byte[] salt, byte[] verifier)
        {
            if (salt == null || salt.Length is 0 or > 255)
                throw new ArgumentException("The salt must be 1 to 255 bytes.", nameof(salt));
            Group = group ?? throw new ArgumentNullException(nameof(group));
            Salt = salt;
            Verifier = verifier ?? throw new ArgumentNullException(nameof(verifier));
        }

        public SrpGroup Group { get; }
        public byte[] Salt { get; }
        public byte[] Verifier { get; }

        /// <summary>The RFC 5054 Appendix A groups, which clients accept.</summary>
        public static IReadOnlyList<SrpGroup> StandardGroups { get; } = new[]
        {
            Srp6StandardGroups.rfc5054_1024, Srp6StandardGroups.rfc5054_1536, Srp6StandardGroups.rfc5054_2048,
            Srp6StandardGroups.rfc5054_3072, Srp6StandardGroups.rfc5054_4096, Srp6StandardGroups.rfc5054_6144,
            Srp6StandardGroups.rfc5054_8192,
        }.Select(SrpGroup.Of).ToArray();

        /// <summary>Creates a verifier with a random 16-byte salt, on the 2048-bit group unless another is given.</summary>
        public static SrpVerifier Create(byte[] identity, byte[] password, SrpGroup group = null)
        {
            group ??= StandardGroups[2];
            byte[] salt = Dtls12CryptoUtils.GenerateRandom(16);
            var generator = new Srp6VerifierGenerator();
            generator.Init(group.Bc, new Sha1Digest());
            return new SrpVerifier(group, salt, BigIntegers.AsUnsignedByteArray(generator.GenerateVerifier(salt, identity, password)));
        }
    }
}
