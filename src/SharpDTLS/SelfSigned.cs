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

        public static (AsymmetricCipherKeyPair keyPair, X509Certificate certificate) Rsa()
        {
            var rsaGenerator = new RsaKeyPairGenerator();
            rsaGenerator.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
            var keyPair = rsaGenerator.GenerateKeyPair();
            return (keyPair, Create(keyPair, "SHA256WITHRSA"));
        }

        public static (AsymmetricCipherKeyPair keyPair, X509Certificate certificate) Ec()
        {
            // Named curve (OID) parameters: RFC 5480 §2.1.1 forbids explicit curve parameters in certificates,
            // and platform validators (e.g. Apple's) reject them.
            var ecGenerator = new ECKeyPairGenerator();
            ecGenerator.Init(new ECKeyGenerationParameters(ECNamedCurveTable.GetOid("P-256"), new SecureRandom()));
            var keyPair = ecGenerator.GenerateKeyPair();
            return (keyPair, Create(keyPair, "SHA256WITHECDSA"));
        }

        private static X509Certificate Create(AsymmetricCipherKeyPair keyPair, string signatureAlgorithm)
        {
            var certGenerator = new X509V3CertificateGenerator();
            certGenerator.SetSerialNumber(BigInteger.ValueOf(1));
            certGenerator.SetIssuerDN(new X509Name("CN=SharpDTLS Server"));
            certGenerator.SetSubjectDN(new X509Name("CN=SharpDTLS Server"));
            certGenerator.SetNotBefore(DateTime.UtcNow.AddDays(-1));
            certGenerator.SetNotAfter(DateTime.UtcNow.AddYears(10));
            certGenerator.SetPublicKey(keyPair.Public);
            return certGenerator.Generate(new Asn1SignatureFactory(signatureAlgorithm, keyPair.Private, new SecureRandom()));
        }
    }
}
