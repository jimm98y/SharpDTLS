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
using System.Linq;

namespace SharpDTLS.Protocol13
{
    /// <summary>
    /// DTLS 1.3 key exchange groups (RFC 8446 §4.2.7): elliptic curves, X25519/X448, RFC 7919 FFDHE, ML-KEM
    /// (draft-ietf-tls-mlkem) and the ECDHE + ML-KEM hybrids (draft-ietf-tls-ecdhe-mlkem).
    /// </summary>
    internal static class Dtls13Groups
    {
        public const ushort Secp256r1 = 0x0017;
        public const ushort Secp384r1 = 0x0018;
        public const ushort Secp521r1 = 0x0019;
        public const ushort X25519 = 0x001d;
        public const ushort X448 = 0x001e;
        public const ushort Ffdhe2048 = 0x0100;
        public const ushort Ffdhe3072 = 0x0101;
        public const ushort Ffdhe4096 = 0x0102;
        public const ushort Ffdhe6144 = 0x0103;
        public const ushort Ffdhe8192 = 0x0104;
        public const ushort MlKem512 = 0x0200;
        public const ushort MlKem768 = 0x0201;
        public const ushort MlKem1024 = 0x0202;
        public const ushort SecP256r1MlKem768 = 0x11eb;
        public const ushort X25519MlKem768 = 0x11ec;
        public const ushort SecP384r1MlKem1024 = 0x11ed;

        /// <summary>Every implemented group.</summary>
        public static IReadOnlyList<ushort> All { get; } = new[]
        {
            X25519MlKem768, SecP256r1MlKem768, SecP384r1MlKem1024, X25519, Secp256r1, Secp384r1, X448, Secp521r1,
            MlKem768, MlKem1024, MlKem512, Ffdhe2048, Ffdhe3072, Ffdhe4096, Ffdhe6144, Ffdhe8192,
        };

        /// <summary>
        /// Default preference: the post-quantum hybrid first, then the elliptic curves, then FFDHE. Pure ML-KEM is
        /// not in it (it has no classical fallback) and must be listed explicitly.
        /// </summary>
        public static IReadOnlyList<ushort> DefaultPreference { get; } = new[]
        {
            X25519MlKem768, X25519, Secp256r1, Secp384r1, X448, Secp521r1, SecP256r1MlKem768, SecP384r1MlKem1024,
            Ffdhe2048, Ffdhe3072, Ffdhe4096,
        };

        public static bool IsSupported(ushort group) => All.Contains(group);

        public static string Name(ushort group) => group switch
        {
            Secp256r1 => "secp256r1", Secp384r1 => "secp384r1", Secp521r1 => "secp521r1", X25519 => "x25519", X448 => "x448",
            Ffdhe2048 => "ffdhe2048", Ffdhe3072 => "ffdhe3072", Ffdhe4096 => "ffdhe4096", Ffdhe6144 => "ffdhe6144", Ffdhe8192 => "ffdhe8192",
            MlKem512 => "MLKEM512", MlKem768 => "MLKEM768", MlKem1024 => "MLKEM1024",
            SecP256r1MlKem768 => "SecP256r1MLKEM768", X25519MlKem768 => "X25519MLKEM768", SecP384r1MlKem1024 => "SecP384r1MLKEM1024",
            _ => $"0x{group:X4}",
        };

        /// <summary>The client's private half of a key share.</summary>
        internal sealed class ClientKeyShare
        {
            public ushort Group { get; set; }
            public byte[] Share { get; set; }
            internal Func<byte[], byte[]> Complete { get; set; }
        }

        /// <summary>Generates the client's key share for <paramref name="group"/>, of <paramref name="crypto"/>'s keys.</summary>
        internal static ClientKeyShare Generate(ushort group, ITlsCrypto crypto = null)
        {
            crypto ??= BouncyCastleTlsCrypto.Default;
            switch (group)
            {
                case X25519MlKem768:
                {
                    // ML-KEM first for X25519MLKEM768: share = ek || x25519, secret = ss || x25519 secret.
                    var kem = Share(crypto, MlKem768);
                    var ecdh = Share(crypto, X25519);
                    return new ClientKeyShare
                    {
                        Group = group,
                        Share = Concat(kem.PublicKey, ecdh.PublicKey),
                        Complete = serverShare =>
                        {
                            BcKeyShares.Expect(serverShare, 1088 + 32);
                            return Concat(Agree(kem, serverShare.AsSpan(0, 1088).ToArray()), Agree(ecdh, serverShare.AsSpan(1088).ToArray()));
                        },
                    };
                }
                case SecP256r1MlKem768:
                case SecP384r1MlKem1024:
                {
                    // ECDH first: share = point || ek, secret = ECDH secret || ss.
                    var ecdh = Share(crypto, group == SecP256r1MlKem768 ? Secp256r1 : Secp384r1);
                    var kem = Share(crypto, group == SecP256r1MlKem768 ? MlKem768 : MlKem1024);
                    int pointLength = group == SecP256r1MlKem768 ? 65 : 97;
                    int ciphertextLength = group == SecP256r1MlKem768 ? 1088 : 1568;
                    return new ClientKeyShare
                    {
                        Group = group,
                        Share = Concat(ecdh.PublicKey, kem.PublicKey),
                        Complete = serverShare =>
                        {
                            BcKeyShares.Expect(serverShare, pointLength + ciphertextLength);
                            return Concat(Agree(ecdh, serverShare.AsSpan(0, pointLength).ToArray()), Agree(kem, serverShare.AsSpan(pointLength).ToArray()));
                        },
                    };
                }
                default:
                {
                    if (!IsSupported(group))
                        throw new DtlsException(AlertDescription.InternalError, $"Group {Name(group)} is not supported.");
                    var share = Share(crypto, group);
                    return new ClientKeyShare { Group = group, Share = share.PublicKey, Complete = peer => Agree(share, peer) };
                }
            }
        }

        /// <summary>The server's side: its key share and the shared secret for the client's <paramref name="clientShare"/>.</summary>
        internal static (byte[] Share, byte[] Secret) Respond(ushort group, byte[] clientShare, ITlsCrypto crypto = null)
        {
            crypto ??= BouncyCastleTlsCrypto.Default;
            switch (group)
            {
                case MlKem512:
                case MlKem768:
                case MlKem1024:
                    return Encapsulate(crypto, group, clientShare);

                case X25519MlKem768:
                {
                    BcKeyShares.Expect(clientShare, 1184 + 32);
                    var (ciphertext, kemSecret) = Encapsulate(crypto, MlKem768, clientShare.AsSpan(0, 1184).ToArray());
                    var (ecdh, ecdhSecret) = RespondClassical(crypto, X25519, clientShare.AsSpan(1184).ToArray());
                    return (Concat(ciphertext, ecdh), Concat(kemSecret, ecdhSecret));
                }
                case SecP256r1MlKem768:
                case SecP384r1MlKem1024:
                {
                    ushort curve = group == SecP256r1MlKem768 ? Secp256r1 : Secp384r1;
                    int pointLength = group == SecP256r1MlKem768 ? 65 : 97;
                    int keyLength = group == SecP256r1MlKem768 ? 1184 : 1568;
                    BcKeyShares.Expect(clientShare, pointLength + keyLength);
                    var (ecdh, ecdhSecret) = RespondClassical(crypto, curve, clientShare.AsSpan(0, pointLength).ToArray());
                    var (ciphertext, kemSecret) = Encapsulate(crypto, group == SecP256r1MlKem768 ? MlKem768 : MlKem1024, clientShare.AsSpan(pointLength).ToArray());
                    return (Concat(ecdh, ciphertext), Concat(ecdhSecret, kemSecret));
                }
                default:
                    return RespondClassical(crypto, group, clientShare);
            }
        }

        private static (byte[] Share, byte[] Secret) RespondClassical(ITlsCrypto crypto, ushort group, byte[] clientShare)
        {
            var share = Share(crypto, group);
            return (share.PublicKey, Agree(share, clientShare));
        }

        // ── Of the crypto provider: its failures for an invalid peer value are illegal_parameter ──

        internal static ITlsKeyShare Share(ITlsCrypto crypto, ushort group)
            => crypto.CreateKeyShare(group) ?? throw new DtlsException(AlertDescription.InternalError, $"Group {Name(group)} is not supported.");

        internal static byte[] Agree(ITlsKeyShare share, byte[] peer)
        {
            try
            {
                return share.Agree(peer);
            }
            catch (System.Security.Cryptography.CryptographicException ex)
            {
                throw new DtlsException(AlertDescription.IllegalParameter, "Invalid key share.", ex);
            }
        }

        private static (byte[] Ciphertext, byte[] Secret) Encapsulate(ITlsCrypto crypto, ushort group, byte[] encapsulationKey)
        {
            try
            {
                byte[] ciphertext = crypto.Encapsulate(group, encapsulationKey, out byte[] secret);
                return (ciphertext, secret);
            }
            catch (System.Security.Cryptography.CryptographicException ex)
            {
                throw new DtlsException(AlertDescription.IllegalParameter, "Invalid ML-KEM encapsulation key.", ex);
            }
        }

        private static byte[] Concat(byte[] a, byte[] b)
        {
            byte[] result = new byte[a.Length + b.Length];
            a.CopyTo(result, 0);
            b.CopyTo(result, a.Length);
            return result;
        }
    }
}
