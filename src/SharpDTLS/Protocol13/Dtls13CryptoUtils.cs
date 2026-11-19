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
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace SharpDTLS.Protocol13
{
    internal static class Dtls13CryptoUtils
    {
        private static readonly byte[] _cookieKey;

        private const byte CookieVersion = 2;
        private static readonly TimeSpan CookieLifetime = TimeSpan.FromMinutes(2);

        static Dtls13CryptoUtils()
        {
            _cookieKey = new byte[32];
            RandomNumberGenerator.Fill(_cookieKey);
        }

        // ── Stateless HelloRetryRequest cookie (RFC 8446 §4.2.2) ────────────────────────────────
        // cookie = version(1) || timestamp(8) || cipher_suite(2) || requested_group(2) || hash_len(1) || Hash(ClientHello1) || HMAC-SHA256(32)
        // The MAC also covers the client address so a cookie cannot be replayed from another address.

        public static byte[] CreateCookie(DateTime timestamp, string clientIP, int clientPort,
            ushort cipherSuite = Dtls13CipherSuite.TLS_AES_128_GCM_SHA256, byte[] clientHelloHash = null, ushort requestedGroup = 0)
        {
            clientHelloHash ??= Array.Empty<byte>();
            byte[] payload = new byte[1 + 8 + 2 + 2 + 1 + clientHelloHash.Length];
            payload[0] = CookieVersion;
            BinaryPrimitives.WriteInt64BigEndian(payload.AsSpan(1, 8), timestamp.ToUniversalTime().Ticks);
            BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(9, 2), cipherSuite);
            BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(11, 2), requestedGroup);
            payload[13] = (byte)clientHelloHash.Length;
            Buffer.BlockCopy(clientHelloHash, 0, payload, 14, clientHelloHash.Length);

            byte[] mac = CookieMac(clientIP, clientPort, payload);
            byte[] cookie = new byte[payload.Length + mac.Length];
            Buffer.BlockCopy(payload, 0, cookie, 0, payload.Length);
            Buffer.BlockCopy(mac, 0, cookie, payload.Length, mac.Length);
            return cookie;
        }

        public static bool ValidateCookie(DateTime now, string clientIP, int clientPort, byte[] cookie,
            out ushort cipherSuite, out byte[] clientHelloHash, out ushort requestedGroup)
        {
            cipherSuite = 0;
            clientHelloHash = null;
            requestedGroup = 0;

            if (cookie == null || cookie.Length < 14 + 32 || cookie[0] != CookieVersion)
                return false;

            int hashLength = cookie[13];
            int payloadLength = 14 + hashLength;
            if (cookie.Length != payloadLength + 32)
                return false;

            byte[] expected = CookieMac(clientIP, clientPort, cookie.AsSpan(0, payloadLength).ToArray());
            if (!CryptographicOperations.FixedTimeEquals(expected, cookie.AsSpan(payloadLength, 32)))
                return false;

            var issued = new DateTime(BinaryPrimitives.ReadInt64BigEndian(cookie.AsSpan(1, 8)), DateTimeKind.Utc);
            var age = now.ToUniversalTime() - issued;
            if (age < TimeSpan.FromSeconds(-5) || age > CookieLifetime)
                return false;

            cipherSuite = BinaryPrimitives.ReadUInt16BigEndian(cookie.AsSpan(9, 2));
            requestedGroup = BinaryPrimitives.ReadUInt16BigEndian(cookie.AsSpan(11, 2));
            clientHelloHash = cookie.AsSpan(14, hashLength).ToArray();
            return true;
        }

        private static byte[] CookieMac(string clientIP, int clientPort, byte[] payload)
        {
            using var hmac = new HMACSHA256(_cookieKey);
            byte[] address = Encoding.UTF8.GetBytes($"{clientIP}:{clientPort}|");
            hmac.TransformBlock(address, 0, address.Length, null, 0);
            hmac.TransformFinalBlock(payload, 0, payload.Length);
            return hmac.Hash;
        }

        // ── Certificates and key exchange ───────────────────────────────────────────────────────





        public static byte[] GenerateRandom(int length)
        {
            var bytes = new byte[length];
            RandomNumberGenerator.Fill(bytes);
            return bytes;
        }


        // ── Key schedule (RFC 8446 §7.1 with the "dtls13" label prefix of RFC 9147 §5.9) ─────────

        /// <summary>
        /// Handshake traffic keys. <paramref name="psk"/> is the resumption PSK (null for a full handshake) and
        /// <paramref name="sharedSecret"/> the (EC)DHE secret (null for psk_ke, which has none).
        /// </summary>
        public static Dtls13CryptoContext CalculateHandshakeKeys(byte[] clientRandom, byte[] helloHash, byte[] sharedSecret, Dtls13CipherSuite suite,
            byte[] psk = null, ITlsCrypto crypto = null)
        {
            crypto ??= BouncyCastleTlsCrypto.Default;
            var earlySecret = CalculateEarlySecret(psk, suite, crypto);
            var derivedSecret = HkdfExpandLabel(earlySecret, suite, "derived", EmptyHash(suite, crypto), suite.HashLength, crypto);
            var handshakeSecret = TlsKdf.HkdfExtract(crypto, suite.HashAlgorithm, derivedSecret, sharedSecret ?? new byte[suite.HashLength]);

            var clientSecret = HkdfExpandLabel(handshakeSecret, suite, "c hs traffic", helloHash, suite.HashLength, crypto);
            var serverSecret = HkdfExpandLabel(handshakeSecret, suite, "s hs traffic", helloHash, suite.HashLength, crypto);

            return CreateContext(clientRandom, handshakeSecret, clientSecret, serverSecret, suite, epoch: 2, crypto);
        }

        public static Dtls13CryptoContext CalculateApplicationKeys(byte[] clientRandom, byte[] handshakeHash, byte[] handshakeSecret, Dtls13CipherSuite suite,
            ITlsCrypto crypto = null)
        {
            crypto ??= BouncyCastleTlsCrypto.Default;
            var derivedSecret = HkdfExpandLabel(handshakeSecret, suite, "derived", EmptyHash(suite, crypto), suite.HashLength, crypto);
            var masterSecret = TlsKdf.HkdfExtract(crypto, suite.HashAlgorithm, derivedSecret, new byte[suite.HashLength]);

            var clientSecret = HkdfExpandLabel(masterSecret, suite, "c ap traffic", handshakeHash, suite.HashLength, crypto);
            var serverSecret = HkdfExpandLabel(masterSecret, suite, "s ap traffic", handshakeHash, suite.HashLength, crypto);

            return CreateContext(clientRandom, masterSecret, clientSecret, serverSecret, suite, epoch: 3, crypto);
        }

        /// <summary>early_secret = HKDF-Extract(0, PSK), with a zero PSK when there is none (RFC 8446 §7.1).</summary>
        public static byte[] CalculateEarlySecret(byte[] psk, Dtls13CipherSuite suite, ITlsCrypto crypto = null)
            => TlsKdf.HkdfExtract(crypto ?? BouncyCastleTlsCrypto.Default, suite.HashAlgorithm, new byte[suite.HashLength], psk ?? new byte[suite.HashLength]);

        /// <summary>
        /// PSK binder (RFC 8446 §4.2.11.2): HMAC(finished_key(Derive-Secret(early_secret, "res binder" or
        /// "ext binder", "")), Transcript-Hash(truncated ClientHello)).
        /// </summary>
        public static byte[] CalculateBinder(byte[] psk, byte[] truncatedTranscriptHash, Dtls13CipherSuite suite, bool external = false, ITlsCrypto crypto = null)
        {
            crypto ??= BouncyCastleTlsCrypto.Default;
            byte[] earlySecret = CalculateEarlySecret(psk, suite, crypto);
            byte[] binderKey = HkdfExpandLabel(earlySecret, suite, external ? "ext binder" : "res binder", EmptyHash(suite, crypto), suite.HashLength, crypto);
            return CalculateFinished(binderKey, truncatedTranscriptHash, suite, crypto);
        }

        /// <summary>
        /// 0-RTT keys (epoch 1, client to server only): client_early_traffic_secret =
        /// Derive-Secret(early_secret, "c e traffic", ClientHello) (RFC 8446 §7.1, RFC 9147 §6.1).
        /// </summary>
        public static Dtls13CryptoContext CalculateEarlyKeys(byte[] clientRandom, byte[] clientHelloHash, byte[] psk, Dtls13CipherSuite suite, ITlsCrypto crypto = null)
        {
            crypto ??= BouncyCastleTlsCrypto.Default;
            byte[] earlySecret = CalculateEarlySecret(psk, suite, crypto);
            byte[] clientSecret = HkdfExpandLabel(earlySecret, suite, "c e traffic", clientHelloHash, suite.HashLength, crypto);
            return CreateContext(clientRandom, earlySecret, clientSecret, clientSecret, suite, epoch: 1, crypto);
        }

        /// <summary>resumption_master_secret = Derive-Secret(master_secret, "res master", ClientHello..client Finished)</summary>
        public static byte[] CalculateResumptionMasterSecret(byte[] masterSecret, byte[] clientFinishedHash, Dtls13CipherSuite suite, ITlsCrypto crypto = null)
            => HkdfExpandLabel(masterSecret, suite, "res master", clientFinishedHash, suite.HashLength, crypto);

        /// <summary>The PSK of one ticket: HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce, Hash.length).</summary>
        public static byte[] CalculateResumptionPsk(byte[] resumptionMasterSecret, byte[] ticketNonce, Dtls13CipherSuite suite, ITlsCrypto crypto = null)
            => HkdfExpandLabel(resumptionMasterSecret, suite, "resumption", ticketNonce, suite.HashLength, crypto);

        /// <summary>exporter_master_secret = Derive-Secret(master_secret, "exp master", ClientHello..server Finished)</summary>
        public static byte[] CalculateExporterMasterSecret(byte[] masterSecret, byte[] handshakeHash, Dtls13CipherSuite suite, ITlsCrypto crypto = null)
            => HkdfExpandLabel(masterSecret, suite, "exp master", handshakeHash, suite.HashLength, crypto);

        /// <summary>
        /// RFC 8446 §7.5: TLS-Exporter(label, context, length) =
        ///   HKDF-Expand-Label(Derive-Secret(exporter_master_secret, label, ""), "exporter", Hash(context), length)
        /// An absent context is treated as empty, as TLS 1.3 does not distinguish them.
        /// </summary>
        public static byte[] ExportKeyingMaterial(byte[] exporterMasterSecret, string label, byte[] context, int length, Dtls13CipherSuite suite,
            ITlsCrypto crypto = null)
        {
            crypto ??= BouncyCastleTlsCrypto.Default;
            byte[] derived = HkdfExpandLabel(exporterMasterSecret, suite, label, EmptyHash(suite, crypto), suite.HashLength, crypto);
            byte[] contextHash = TlsKdf.Hash(crypto, suite.HashAlgorithm, context ?? Array.Empty<byte>());
            return HkdfExpandLabel(derived, suite, "exporter", contextHash, length, crypto);
        }

        private static Dtls13CryptoContext CreateContext(byte[] clientRandom, byte[] secret, byte[] clientSecret, byte[] serverSecret, Dtls13CipherSuite suite,
            ulong epoch, ITlsCrypto crypto)
        {
            var (clientKey, clientIv, clientSnKey) = DeriveTrafficKeys(clientSecret, suite, crypto);
            var (serverKey, serverIv, serverSnKey) = DeriveTrafficKeys(serverSecret, suite, crypto);
            return new Dtls13CryptoContext(clientRandom, secret, clientSecret, serverSecret, clientKey, clientIv, serverKey, serverIv, clientSnKey, serverSnKey, suite, epoch)
            {
                Crypto = crypto,
            };
        }

        private static (byte[] key, byte[] iv, byte[] snKey) DeriveTrafficKeys(byte[] trafficSecret, Dtls13CipherSuite suite, ITlsCrypto crypto)
        {
            byte[] key   = HkdfExpandLabel(trafficSecret, suite, "key", Array.Empty<byte>(), suite.KeyLength, crypto);
            byte[] iv    = HkdfExpandLabel(trafficSecret, suite, "iv", Array.Empty<byte>(), suite.IvLength, crypto);
            byte[] snKey = HkdfExpandLabel(trafficSecret, suite, "sn", Array.Empty<byte>(), suite.KeyLength, crypto);
            return (key, iv, snKey);
        }

        /// <summary>verify_data = HMAC(finished_key, transcript_hash), finished_key = HKDF-Expand-Label(base_key, "finished", "", Hash.length)</summary>
        public static byte[] CalculateFinished(byte[] baseKey, byte[] transcriptHash, Dtls13CipherSuite suite, ITlsCrypto crypto = null)
        {
            crypto ??= BouncyCastleTlsCrypto.Default;
            byte[] finishedKey = HkdfExpandLabel(baseKey, suite, "finished", Array.Empty<byte>(), suite.HashLength, crypto);
            return TlsKdf.Hmac(crypto, suite.HashAlgorithm, finishedKey, transcriptHash);
        }

        // RFC 8446 §7.2: application_traffic_secret_N+1 = HKDF-Expand-Label(application_traffic_secret_N, "traffic upd", "", Hash.length)
        // RFC 9147 §8: each KeyUpdate moves that direction to the next epoch.
        public static Dtls13CryptoContext UpdateClientTrafficSecret(Dtls13CryptoContext current)
        {
            var suite = current.Suite;
            var crypto = current.Crypto;
            var newClientSecret = HkdfExpandLabel(current.ClientSecret, suite, "traffic upd", Array.Empty<byte>(), suite.HashLength, crypto);
            var (key, iv, snKey) = DeriveTrafficKeys(newClientSecret, suite, crypto);

            return new Dtls13CryptoContext(
                current.ClientRandom, current.Secret,
                newClientSecret, current.ServerSecret,
                key, iv,
                current.ServerKey, current.ServerIv,
                snKey, current.ServerSnKey,
                suite, current.Epoch + 1)
            {
                Crypto = crypto,
            };
        }

        public static Dtls13CryptoContext UpdateServerTrafficSecret(Dtls13CryptoContext current)
        {
            var suite = current.Suite;
            var crypto = current.Crypto;
            var newServerSecret = HkdfExpandLabel(current.ServerSecret, suite, "traffic upd", Array.Empty<byte>(), suite.HashLength, crypto);
            var (key, iv, snKey) = DeriveTrafficKeys(newServerSecret, suite, crypto);

            return new Dtls13CryptoContext(
                current.ClientRandom, current.Secret,
                current.ClientSecret, newServerSecret,
                current.ClientKey, current.ClientIv,
                key, iv,
                current.ClientSnKey, snKey,
                suite, current.Epoch + 1)
            {
                Crypto = crypto,
            };
        }

        private static byte[] EmptyHash(Dtls13CipherSuite suite, ITlsCrypto crypto) => TlsKdf.Hash(crypto, suite.HashAlgorithm, Array.Empty<byte>());

        /// <summary>
        /// HKDF-Expand-Label (RFC 8446 §7.1) with the suite's hash and label prefix: "dtls13" (RFC 9147 §5.9), or "tls13 "
        /// for TLS.
        /// </summary>
        internal static byte[] HkdfExpandLabel(byte[] secret, Dtls13CipherSuite suite, string label, byte[] context, int length, ITlsCrypto crypto = null)
        {
            byte[] prefix = suite.LabelPrefixBytes;
            int expandedLabelLength = prefix.Length + label.Length;
            if (label.Length < 1 || expandedLabelLength > 255 || context.Length > 255 || length > 0xFFFF)
                throw new DtlsException(AlertDescription.InternalError, "HKDF-Expand-Label out of range.");

            // uint16 length || opaque label<7..255> || opaque context<0..255>
            byte[] hkdfLabel = new byte[2 + 1 + expandedLabelLength + 1 + context.Length];
            BinaryPrimitives.WriteUInt16BigEndian(hkdfLabel, (ushort)length);
            hkdfLabel[2] = (byte)expandedLabelLength;
            prefix.CopyTo(hkdfLabel, 3);
            for (int i = 0; i < label.Length; ++i)
                hkdfLabel[3 + prefix.Length + i] = (byte)label[i];
            hkdfLabel[3 + expandedLabelLength] = (byte)context.Length;
            context.CopyTo(hkdfLabel, 4 + expandedLabelLength);

            return TlsKdf.HkdfExpand(crypto ?? BouncyCastleTlsCrypto.Default, suite.HashAlgorithm, secret, hkdfLabel, length);
        }
    }
}
