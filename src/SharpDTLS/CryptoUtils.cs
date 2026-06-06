using SharpDTLS.DTLS13;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using SharpDTLS.DTLS13.Messages;

namespace SharpDTLS
{
    public static class CryptoUtils
    {
        private static readonly byte[] _privateKey;

        static CryptoUtils()
        {
            _privateKey = new byte[32];
            new SecureRandom().NextBytes(_privateKey);
        }

        public static byte[] CreateCookie(DateTime timestamp, string clientIP, int clientPort, int minuteTimeOffset = 0)
        {
            DateTime timestampRounded = new DateTime(timestamp.Year, timestamp.Month, timestamp.Day, timestamp.Hour, timestamp.Minute, 0, DateTimeKind.Utc);
            timestampRounded = timestampRounded.AddMinutes(minuteTimeOffset);

            string data = $"{clientIP}:{clientPort}:{timestampRounded.ToFileTime()}";
            using (var hmac = new HMACSHA256(_privateKey))
            {
                return hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(data));
            }
        }

        public static bool ValidateCookie(DateTime timestamp, string clientIP, int clientPort, byte[] cookie)
        {
            byte[] expectedCookie = CreateCookie(timestamp, clientIP, clientPort);
            if(expectedCookie.SequenceEqual(cookie))
            {
                return true;
            }
            else
            {
                expectedCookie = CreateCookie(timestamp, clientIP, clientPort, -1);
                return expectedCookie.SequenceEqual(cookie);
            }
        }

        public static (X25519PrivateKeyParameters privateX25519, X25519PublicKeyParameters publicX25519) CreateX25519KeyPair()
        {
            X25519KeyPairGenerator x25519KeyPairGenerator = new X25519KeyPairGenerator();
            x25519KeyPairGenerator.Init(new X25519KeyGenerationParameters(new SecureRandom()));
            AsymmetricCipherKeyPair keyPair = x25519KeyPairGenerator.GenerateKeyPair();
            return (keyPair.Private as X25519PrivateKeyParameters, keyPair.Public as X25519PublicKeyParameters);
        }

        public static byte[] GenerateRandom(int length)
        {
            var clientRandom = new byte[length];
            var secureRandom = new SecureRandom();
            secureRandom.NextBytes(clientRandom);
            return clientRandom;
        }

        public static byte[] DeriveSharedSecretX25519(byte[] privateKey, byte[] publicKey)
        {
            if (privateKey == null) throw new ArgumentNullException(nameof(privateKey));
            if (publicKey == null) throw new ArgumentNullException(nameof(publicKey));
            if (privateKey.Length != 32) throw new ArgumentException("Private key must be 32 bytes.", nameof(privateKey));
            if (publicKey.Length != 32) throw new ArgumentException("Public key must be 32 bytes.", nameof(publicKey));

            var priv = new X25519PrivateKeyParameters(privateKey, 0);
            var pub = new X25519PublicKeyParameters(publicKey, 0);

            var shared = new byte[32];
            priv.GenerateSecret(pub, shared, 0);
            return shared;
        }

        public static byte[] CalculateHelloHash(byte[] clientHelloBytes, byte[] serverHelloBytes)
        {
            // skipping DTLS-specific bytes 
            byte[] clientHello = clientHelloBytes.Skip(13).Take(4).Concat(clientHelloBytes.Skip(13 + 4 + 8)).ToArray();
            byte[] serverHello = serverHelloBytes.Skip(13).Take(4).Concat(serverHelloBytes.Skip(13 + 4 + 8)).ToArray();
            byte[] helloHash = SHA256.HashData(clientHello.Concat(serverHello).ToArray());
            return helloHash;
        }

        public static Dtls13CryptoContext CalculateHandshakeKeys(byte[] clientRandom, byte[] helloHash, byte[] sharedSecret)
        {
            var crypto = new BcTlsCrypto();
            var hashAlg = CryptoHashAlgorithm.sha256;
            byte[] zeroKey = new byte[32];

            var earlySecret = (new BcTlsSecret(crypto, new byte[] { 0x00 })).HkdfExtract(hashAlg, new BcTlsSecret(crypto, zeroKey)).Extract();

            var emptyHash = SHA256.HashData(Array.Empty<byte>());
            var derivedSecret = HkdfExpandLabel(new BcTlsSecret(crypto, earlySecret), hashAlg, "derived", emptyHash, 32).Extract();

            var handshakeSecret = (new BcTlsSecret(crypto, derivedSecret)).HkdfExtract(hashAlg, new BcTlsSecret(crypto, sharedSecret)).Extract();

            var clientSecret = HkdfExpandLabel(new BcTlsSecret(crypto, handshakeSecret), hashAlg, "c hs traffic", helloHash, 32).Extract();
            var serverSecret = HkdfExpandLabel(new BcTlsSecret(crypto, handshakeSecret), hashAlg, "s hs traffic", helloHash, 32).Extract();
            var clientKey = HkdfExpandLabel(new BcTlsSecret(crypto, clientSecret), hashAlg, "key", new byte[0], 16).Extract();
            var serverKey = HkdfExpandLabel(new BcTlsSecret(crypto, serverSecret), hashAlg, "key", new byte[0], 16).Extract();
            var clientIv = HkdfExpandLabel(new BcTlsSecret(crypto, clientSecret), hashAlg, "iv", new byte[0], 12).Extract();
            var serverIv = HkdfExpandLabel(new BcTlsSecret(crypto, serverSecret), hashAlg, "iv", new byte[0], 12).Extract();
            var clientSnKey = HkdfExpandLabel(new BcTlsSecret(crypto, clientSecret), hashAlg, "sn", new byte[0], 16).Extract();
            var serverSnKey = HkdfExpandLabel(new BcTlsSecret(crypto, serverSecret), hashAlg, "sn", new byte[0], 16).Extract();

            return new Dtls13CryptoContext(clientRandom, handshakeSecret, clientSecret, serverSecret, clientKey, clientIv, serverKey, serverIv, clientSnKey, serverSnKey);
        }

        public static Dtls13CryptoContext CalculateApplicationKeys(byte[] clientRandom, byte[] handshakeHash, byte[] handshakeSecret)
        {
            var crypto = new BcTlsCrypto();
            var hashAlg = CryptoHashAlgorithm.sha256;
            byte[] zeroKey = new byte[32];

            var emptyHash = SHA256.HashData(Array.Empty<byte>());
            var derivedSecret = HkdfExpandLabel(new BcTlsSecret(crypto, handshakeSecret), hashAlg, "derived", emptyHash, 32).Extract();

            var masterSecret = (new BcTlsSecret(crypto, derivedSecret)).HkdfExtract(hashAlg, new BcTlsSecret(crypto, zeroKey)).Extract();

            var clientSecret = HkdfExpandLabel(new BcTlsSecret(crypto, masterSecret), hashAlg, "c ap traffic", handshakeHash, 32).Extract();
            var serverSecret = HkdfExpandLabel(new BcTlsSecret(crypto, masterSecret), hashAlg, "s ap traffic", handshakeHash, 32).Extract();
            var clientKey = HkdfExpandLabel(new BcTlsSecret(crypto, clientSecret), hashAlg, "key", new byte[0], 16).Extract();
            var serverKey = HkdfExpandLabel(new BcTlsSecret(crypto, serverSecret), hashAlg, "key", new byte[0], 16).Extract();
            var clientIv = HkdfExpandLabel(new BcTlsSecret(crypto, clientSecret), hashAlg, "iv", new byte[0], 12).Extract();
            var serverIv = HkdfExpandLabel(new BcTlsSecret(crypto, serverSecret), hashAlg, "iv", new byte[0], 12).Extract();
            var clientSnKey = HkdfExpandLabel(new BcTlsSecret(crypto, clientSecret), hashAlg, "sn", new byte[0], 16).Extract();
            var serverSnKey = HkdfExpandLabel(new BcTlsSecret(crypto, serverSecret), hashAlg, "sn", new byte[0], 16).Extract();

            return new Dtls13CryptoContext(clientRandom, masterSecret, clientSecret, serverSecret, clientKey, clientIv, serverKey, serverIv, clientSnKey, serverSnKey);
        }

        // we have to duplicate the HkdfExpandLabel method because we need a different prefix for DTLS 1.3
        private readonly static byte[] Dtls13Prefix = System.Text.Encoding.ASCII.GetBytes("dtls13");

        /// <exception cref="IOException"/>
        public static TlsSecret HkdfExpandLabel(TlsSecret secret, int cryptoHashAlgorithm, string label,
            byte[] context, int length)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return HkdfExpandLabel(secret, cryptoHashAlgorithm, label.AsSpan(), context.AsSpan(), length);
#else
            int labelLength = label.Length;
            if (labelLength < 1)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            int contextLength = context.Length;
            int expandedLabelLength = Dtls13Prefix.Length + labelLength;

            byte[] hkdfLabel = new byte[2 + (1 + expandedLabelLength) + (1 + contextLength)];

            // uint16 length
            {
                TlsUtilities.CheckUint16(length);
                TlsUtilities.WriteUint16(length, hkdfLabel, 0);
            }

            // opaque label<7..255>
            {
                TlsUtilities.CheckUint8(expandedLabelLength);
                TlsUtilities.WriteUint8(expandedLabelLength, hkdfLabel, 2);

                Array.Copy(Dtls13Prefix, 0, hkdfLabel, 2 + 1, Dtls13Prefix.Length);

                int labelPos = 2 + (1 + Dtls13Prefix.Length);
                for (int i = 0; i < labelLength; ++i)
                {
                    char c = label[i];
                    hkdfLabel[labelPos + i] = (byte)c;
                }
            }

            // context
            {
                TlsUtilities.WriteOpaque8(context, hkdfLabel, 2 + (1 + expandedLabelLength));
            }

            return secret.HkdfExpand(cryptoHashAlgorithm, hkdfLabel, length);
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <exception cref="IOException"/>
        public static TlsSecret HkdfExpandLabel(TlsSecret secret, int cryptoHashAlgorithm, ReadOnlySpan<char> label,
            ReadOnlySpan<byte> context, int length)
        {
            int labelLength = label.Length;
            if (labelLength < 1)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            int contextLength = context.Length;
            int expandedLabelLength = Dtls13Prefix.Length + labelLength;

            int hkdfLabelLength = 2 + (1 + expandedLabelLength) + (1 + contextLength);
            Span<byte> hkdfLabel = hkdfLabelLength <= 512
                ? stackalloc byte[hkdfLabelLength]
                : new byte[hkdfLabelLength];

            // uint16 length
            {
                TlsUtilities.CheckUint16(length);
                TlsUtilities.WriteUint16(length, hkdfLabel);
            }

            // opaque label<7..255>
            {
                TlsUtilities.CheckUint8(expandedLabelLength);
                TlsUtilities.WriteUint8(expandedLabelLength, hkdfLabel[2..]);

                Dtls13Prefix.CopyTo(hkdfLabel[3..]);

                int labelPos = 2 + (1 + Dtls13Prefix.Length);
                for (int i = 0; i < labelLength; ++i)
                {
                    hkdfLabel[labelPos + i] = (byte)label[i];
                }
            }

            // context
            {
                TlsUtilities.WriteOpaque8(context, hkdfLabel.Slice(2 + (1 + expandedLabelLength)));
            }

            return secret.HkdfExpand(cryptoHashAlgorithm, hkdfLabel, length);
        }
#endif

        public static byte[] HashAllMessages(List<IDatagram> handshakeMessages)
        {
            Sha256Digest hash = new Sha256Digest();

            foreach (IDatagram msg in handshakeMessages)
            {
                IDatagram msgToHash = msg;
                int skip;
                int last;
                if (msg is ClientHelloDatagram || msg is ServerHelloDatagram)
                {
                    skip = 13;
                    last = 0;
                }
                else
                {
                    skip = 0;
                    last = 1;
                    if (msg is ServerEncryptedDatagram msgServer)
                    {
                        msgToHash = msgServer.Datagram;
                    }
                    else if(msg is ClientEncryptedDatagram msgClient)
                    {
                        msgToHash = msgClient.Datagram;
                    }
                    else
                    {
                        throw new NotSupportedException();
                    }
                }

                var msgBytes = msgToHash.Bytes.Skip(skip).Take(4).Concat(msgToHash.Bytes.Skip(skip + 4 + 8).Take(msgToHash.Bytes.Length - skip - 4 - 8 - last)).ToArray();
                hash.BlockUpdate(msgBytes, 0, msgBytes.Length);
            }

            byte[] h = new byte[hash.GetDigestSize()];
            hash.DoFinal(h, 0);
            return h;
        }

        public static byte[] CalculateHmac(byte[] key, byte[] data)
        {
            var hmac = new HMac(new Sha256Digest());
            hmac.Init(new KeyParameter(key));
            byte[] mac = new byte[hmac.GetMacSize()];
            hmac.BlockUpdate(data, 0, data.Length);
            hmac.DoFinal(mac, 0);
            return mac;
        }
    }
}
