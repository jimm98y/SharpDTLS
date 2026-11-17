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

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;

namespace SharpDTLS
{
    /// <summary>The self-signed certificates of servers given none, of BouncyCastle (so of every framework).</summary>
    internal static class SelfSigned
    {
        /// <summary>An RSA-2048 certificate and its key, the default of a server with no credentials.</summary>
        public static ServerCredentials Credentials()
        {
            var (keyPair, certificate) = Rsa();
            return new ServerCredentials(keyPair, certificate);
        }

        public static (AsymmetricCipherKeyPair keyPair, X509Certificate certificate) Rsa(string hostName = null, int keySize = 2048)
        {
            var rsaGenerator = new RsaKeyPairGenerator();
            rsaGenerator.Init(new KeyGenerationParameters(new SecureRandom(), keySize));
            var keyPair = rsaGenerator.GenerateKeyPair();
            return (keyPair, Create(keyPair, "SHA256WITHRSA", hostName));
        }

        /// <summary>ECDSA on <paramref name="curve"/> (P-256 unless named), signed with the hash of the curve's size.</summary>
        public static (AsymmetricCipherKeyPair keyPair, X509Certificate certificate) Ec(string hostName = null, DerObjectIdentifier curve = null)
        {
            // Named curve (OID) parameters: RFC 5480 §2.1.1 forbids explicit curve parameters in certificates,
            // and platform validators (e.g. Apple's) reject them.
            curve ??= ECNamedCurveTable.GetOid("P-256");
            var parameters = ECNamedCurveTable.GetByOid(curve) ?? throw new ArgumentException($"Unknown curve {curve}.", nameof(curve));
            var ecGenerator = new ECKeyPairGenerator();
            ecGenerator.Init(new ECKeyGenerationParameters(curve, new SecureRandom()));
            var keyPair = ecGenerator.GenerateKeyPair();
            int bits = parameters.Curve.FieldSize;
            string hash = bits <= 256 ? "SHA256" : bits <= 384 ? "SHA384" : "SHA512";
            return (keyPair, Create(keyPair, hash + "WITHECDSA", hostName));
        }

        private static X509Certificate Create(AsymmetricCipherKeyPair keyPair, string signatureAlgorithm, string hostName)
        {
            // the name as a value, not parsed: a host name of ',' or '=' adds no attribute
            var name = new X509Name(new[] { X509Name.CN }, new[] { hostName ?? "SharpDTLS Server" });
            var certGenerator = new X509V3CertificateGenerator();
            // random: two certificates of one issuer and serial number are refused by some clients (Firefox)
            certGenerator.SetSerialNumber(BigInteger.ProbablePrime(64, new SecureRandom()));
            certGenerator.SetIssuerDN(name);
            certGenerator.SetSubjectDN(name);
            certGenerator.SetNotBefore(DateTime.UtcNow.AddDays(-1));
            certGenerator.SetNotAfter(DateTime.UtcNow.AddYears(10));
            certGenerator.SetPublicKey(keyPair.Public);
            if (hostName != null)
                certGenerator.AddExtension(X509Extensions.SubjectAlternativeName, false, new GeneralNames(new GeneralName(GeneralName.DnsName, hostName)));
            return certGenerator.Generate(new Asn1SignatureFactory(signatureAlgorithm, keyPair.Private, new SecureRandom()));
        }
    }
}
