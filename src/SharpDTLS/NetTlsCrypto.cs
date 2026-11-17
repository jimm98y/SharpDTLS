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

using SharpDTLS.Protocol13;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SharpDTLS
{
    /// <summary>
    /// An <see cref="ITlsCrypto"/> that signs and decrypts with the certificate's own <see cref="RSA"/> or <see cref="ECDsa"/>,
    /// and on .NET 8+ its own <see cref="DSA"/> and <see cref="ECDiffieHellman"/> (static ECDH), so its key need not be
    /// exportable (the Windows certificate store, a TPM, smart cards, HSMs). What .NET has no key for (PKCS#8 keys, Ed25519,
    /// Ed448, DH) and the MD5 || SHA-1 RSA signature of TLS 1.0/1.1 are left to <see cref="BouncyCastleTlsCrypto"/>. RSA key transport is the platform's PKCS#1 v1.5 decryption, whose failures may
    /// take longer than successes; prefer the ECDHE and DHE cipher suites, as the defaults do.
    /// On .NET 8 and later, records are protected by .NET's AES-GCM, AES-CCM and ChaCha20-Poly1305 where the platform has
    /// them, which allocate nothing per record, and hashed by .NET's hashes and HMACs.
    /// </summary>
    public class NetTlsCrypto : BouncyCastleTlsCrypto
    {
        public override byte[] Sign(TransportCertificate credentials, ushort scheme, byte[] content)
        {
            if (!OwnKey(credentials))
                return base.Sign(credentials, scheme, content);
            HashAlgorithmName hash = (scheme >> 8, scheme & 0xFF) switch
            {
                (2, _) => HashAlgorithmName.SHA1,
                (4, _) or (8, 4) => HashAlgorithmName.SHA256,
                (5, _) or (8, 5) => HashAlgorithmName.SHA384,
                (6, _) or (8, 6) => HashAlgorithmName.SHA512,
                _ => default,
            };
            bool pss = scheme is SignatureSchemes.RsaPssRsaeSha256 or SignatureSchemes.RsaPssRsaeSha384 or SignatureSchemes.RsaPssRsaeSha512;
            if (hash.Name != null && (pss || (scheme & 0xFF) == 1))
            {
                using var rsa = credentials.Certificate.GetRSAPrivateKey();
                if (rsa != null)
                    return rsa.SignData(content, hash, pss ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1);
            }
            else if (hash.Name != null && (scheme & 0xFF) == 3)
            {
                using var ecdsa = credentials.Certificate.GetECDsaPrivateKey();
                if (ecdsa != null)
                {
#if NETCOREAPP
                    return ecdsa.SignData(content, hash, DSASignatureFormat.Rfc3279DerSequence);
#else
                    // IEEE P1363 r || s, as TLS has it: a DER SEQUENCE of the two INTEGERs
                    byte[] rs = ecdsa.SignData(content, hash);
                    return DerSignature(rs.AsSpan(0, rs.Length / 2), rs.AsSpan(rs.Length / 2));
#endif
                }
            }
#if NETCOREAPP
            else if (hash.Name != null && (scheme & 0xFF) == 2)
            {
                using var dsa = credentials.Certificate.GetDSAPrivateKey();
                if (dsa != null)
                    return dsa.SignData(content, hash, DSASignatureFormat.Rfc3279DerSequence);
            }
#endif
            return base.Sign(credentials, scheme, content);
        }

        // Static ECDH (the ECDH_ECDSA and ECDH_RSA suites) of the certificate's own key, on .NET 8+
        public override byte[] Agree(TransportCertificate credentials, byte[] peerPublicKey)
        {
#if NETCOREAPP
            using var ecdh = OwnKey(credentials) ? credentials.Certificate.GetECDiffieHellmanPrivateKey() : null;
            if (ecdh != null)
            {
                var curve = ecdh.ExportParameters(false).Curve;
                int fieldLength = (peerPublicKey.Length - 1) / 2;
                if (peerPublicKey.Length < 3 || peerPublicKey[0] != 0x04 || peerPublicKey.Length != 1 + 2 * fieldLength)
                    throw new DtlsException(AlertDescription.IllegalParameter, "Invalid EC point encoding.");
                var peer = new ECParameters
                {
                    Curve = curve,
                    Q = new ECPoint { X = peerPublicKey.AsSpan(1, fieldLength).ToArray(), Y = peerPublicKey.AsSpan(1 + fieldLength).ToArray() },
                };
                try
                {
                    // the import refuses a point off the curve
                    using var peerKey = ECDiffieHellman.Create(peer);
                    return ecdh.DeriveRawSecretAgreement(peerKey.PublicKey);
                }
                catch (CryptographicException ex)
                {
                    throw new DtlsException(AlertDescription.IllegalParameter, "EC point is not on the curve.", ex);
                }
            }
#endif
            return base.Agree(credentials, peerPublicKey);
        }

        public override byte[] DecryptPreMasterSecret(TransportCertificate credentials, byte[] encrypted)
        {
            using var rsa = OwnKey(credentials) ? credentials.Certificate.GetRSAPrivateKey() : null;
            if (rsa == null)
                return base.DecryptPreMasterSecret(credentials, encrypted);
            try
            {
                return rsa.Decrypt(encrypted, RSAEncryptionPadding.Pkcs1);
            }
            catch (System.Exception ex) when (ex is not CryptographicException)
            {
                throw new CryptographicException("RSA decryption failed.", ex);
            }
        }

        // .NET Framework and .NET Standard have no AEAD and no span hashes: BouncyCastle's there
        public override ITlsAead CreateAead(TlsAeadAlgorithm algorithm, ReadOnlySpan<byte> key)
#if NETCOREAPP
            => (ITlsAead)NetAead.Create(algorithm, key) ?? base.CreateAead(algorithm, key);
#else
            => base.CreateAead(algorithm, key);
#endif

        public override ITlsHash CreateHash(TlsHashAlgorithm hash)
#if NETCOREAPP
            => new NetHash(hash, default, hmac: false);
#else
            => base.CreateHash(hash);
#endif

        public override ITlsHash CreateHmac(TlsHashAlgorithm hash, ReadOnlySpan<byte> key)
#if NETCOREAPP
            => new NetHash(hash, key, hmac: true);
#else
            => base.CreateHmac(hash, key);
#endif

        // RSA (PKCS#1 v1.5, PSS of rsaEncryption keys) and ECDSA of .NET on .NET 8+; the rest of BouncyCastle
        public override bool Verify(ushort scheme, byte[] subjectPublicKeyInfo, byte[] content, byte[] signature)
        {
#if NETCOREAPP
            HashAlgorithmName hash = Hash(scheme);
            bool pss = scheme is SignatureSchemes.RsaPssRsaeSha256 or SignatureSchemes.RsaPssRsaeSha384 or SignatureSchemes.RsaPssRsaeSha512;
            if (hash.Name != null && (pss || (scheme & 0xFF) == 1 || (scheme & 0xFF) == 3))
            {
                var key = PublicKey.CreateFromSubjectPublicKeyInfo(subjectPublicKeyInfo, out _);
                try
                {
                    if ((scheme & 0xFF) == 3)
                    {
                        using var ecdsa = key.GetECDsaPublicKey();
                        if (ecdsa != null)
                            return ecdsa.VerifyData(content, signature, hash, DSASignatureFormat.Rfc3279DerSequence);
                    }
                    else
                    {
                        using var rsa = key.GetRSAPublicKey();
                        if (rsa != null)
                            return rsa.VerifyData(content, signature, hash, pss ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1);
                    }
                }
                catch (CryptographicException)
                {
                    return false;
                }
            }
#endif
            return base.Verify(scheme, subjectPublicKeyInfo, content, signature);
        }

        public override byte[] EncryptPreMasterSecret(byte[] subjectPublicKeyInfo, byte[] preMasterSecret)
        {
#if NETCOREAPP
            var key = PublicKey.CreateFromSubjectPublicKeyInfo(subjectPublicKeyInfo, out _);
            using var rsa = key.GetRSAPublicKey();
            if (rsa != null)
                return rsa.Encrypt(preMasterSecret, RSAEncryptionPadding.Pkcs1);
#endif
            return base.EncryptPreMasterSecret(subjectPublicKeyInfo, preMasterSecret);
        }

        private static HashAlgorithmName Hash(ushort scheme) => (scheme >> 8, scheme & 0xFF) switch
        {
            (2, _) => HashAlgorithmName.SHA1,
            (4, _) or (8, 4) => HashAlgorithmName.SHA256,
            (5, _) or (8, 5) => HashAlgorithmName.SHA384,
            (6, _) or (8, 6) => HashAlgorithmName.SHA512,
            _ => default,
        };

        // static ECDH's ephemeral key on a NIST curve of .NET's ECDiffieHellman on .NET 8+
        public override ITlsKeyShare CreateKeyShareOnDomainOf(byte[] subjectPublicKeyInfo)
        {
#if NETCOREAPP
            ushort group = TlsPublicKey.FromSpki(subjectPublicKeyInfo).CurveOid switch
            {
                "1.2.840.10045.3.1.7" => Dtls13Groups.Secp256r1,
                "1.3.132.0.34" => Dtls13Groups.Secp384r1,
                "1.3.132.0.35" => Dtls13Groups.Secp521r1,
                _ => 0,
            };
            if (group != 0)
                return NetKeyShares.Create(group);
#endif
            return base.CreateKeyShareOnDomainOf(subjectPublicKeyInfo);
        }

        // ECDHE of .NET's ECDiffieHellman on .NET 8+; X25519, X448, FFDHE and ML-KEM of BouncyCastle
        public override ITlsKeyShare CreateKeyShare(ushort group)
#if NETCOREAPP
            => NetKeyShares.Create(group) ?? base.CreateKeyShare(group);
#else
            => base.CreateKeyShare(group);
#endif

#if !NETCOREAPP
        // SEQUENCE { INTEGER r, INTEGER s }, of r and s unsigned big-endian (lengths under 128 bytes: up to P-521)
        private static byte[] DerSignature(ReadOnlySpan<byte> r, ReadOnlySpan<byte> s)
        {
            byte[] a = DerInteger(r), b = DerInteger(s);
            var sequence = new byte[2 + a.Length + b.Length + (a.Length + b.Length >= 128 ? 1 : 0)];
            int i = 0;
            sequence[i++] = 0x30;
            if (a.Length + b.Length >= 128)
                sequence[i++] = 0x81;
            sequence[i++] = (byte)(a.Length + b.Length);
            a.CopyTo(sequence, i);
            b.CopyTo(sequence, i + a.Length);
            return sequence;
        }

        private static byte[] DerInteger(ReadOnlySpan<byte> value)
        {
            while (value.Length > 1 && value[0] == 0)
                value = value.Slice(1);
            bool pad = (value[0] & 0x80) != 0;
            var integer = new byte[2 + value.Length + (pad ? 1 : 0)];
            integer[0] = 0x02;
            integer[1] = (byte)(value.Length + (pad ? 1 : 0));
            value.CopyTo(integer.AsSpan(2 + (pad ? 1 : 0)));
            return integer;
        }
#endif

        // The certificate holds the key, and BouncyCastle has none of it: of PKCS#8, or of the engines' key pairs.
        private static bool OwnKey(TransportCertificate credentials)
            => credentials.Certificate != null && credentials.Certificate.HasPrivateKey && !credentials.HasPkcs8PrivateKey && credentials.KeyPair == null;
    }
}
