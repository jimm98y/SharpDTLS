using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.X509;
using System;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace SharpDTLS.DTLS13
{
    public static class Dtls13CryptoUtils
    {
        private static readonly byte[] _cookieKey;
        private static readonly BcTlsCrypto _crypto = new BcTlsCrypto();

        private const byte CookieVersion = 1;
        private static readonly TimeSpan CookieLifetime = TimeSpan.FromMinutes(2);

        static Dtls13CryptoUtils()
        {
            _cookieKey = new byte[32];
            new SecureRandom().NextBytes(_cookieKey);
        }

        // ── Stateless HelloRetryRequest cookie (RFC 8446 §4.2.2) ────────────────────────────────
        // cookie = version(1) || timestamp(8) || cipher_suite(2) || flags(1) || hash_len(1) || Hash(ClientHello1) || HMAC-SHA256(32)
        // The MAC also covers the client address so a cookie cannot be replayed from another address.

        public static byte[] CreateCookie(DateTime timestamp, string clientIP, int clientPort,
            ushort cipherSuite = Dtls13CipherSuite.TLS_AES_128_GCM_SHA256, byte[] clientHelloHash = null, bool keyShareRequested = false)
        {
            clientHelloHash ??= Array.Empty<byte>();
            byte[] payload = new byte[1 + 8 + 2 + 1 + 1 + clientHelloHash.Length];
            payload[0] = CookieVersion;
            BinaryPrimitives.WriteInt64BigEndian(payload.AsSpan(1, 8), timestamp.ToUniversalTime().Ticks);
            BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(9, 2), cipherSuite);
            payload[11] = (byte)(keyShareRequested ? 1 : 0);
            payload[12] = (byte)clientHelloHash.Length;
            Buffer.BlockCopy(clientHelloHash, 0, payload, 13, clientHelloHash.Length);

            byte[] mac = CookieMac(clientIP, clientPort, payload);
            byte[] cookie = new byte[payload.Length + mac.Length];
            Buffer.BlockCopy(payload, 0, cookie, 0, payload.Length);
            Buffer.BlockCopy(mac, 0, cookie, payload.Length, mac.Length);
            return cookie;
        }

        public static bool ValidateCookie(DateTime now, string clientIP, int clientPort, byte[] cookie,
            out ushort cipherSuite, out byte[] clientHelloHash, out bool keyShareRequested)
        {
            cipherSuite = 0;
            clientHelloHash = null;
            keyShareRequested = false;

            if (cookie == null || cookie.Length < 13 + 32 || cookie[0] != CookieVersion)
                return false;

            int hashLength = cookie[12];
            int payloadLength = 13 + hashLength;
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
            keyShareRequested = cookie[11] == 1;
            clientHelloHash = cookie.AsSpan(13, hashLength).ToArray();
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

        public static (AsymmetricCipherKeyPair keyPair, X509Certificate certificate) GenerateSelfSignedCertificate()
        {
            var rsaGenerator = new RsaKeyPairGenerator();
            rsaGenerator.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
            var keyPair = rsaGenerator.GenerateKeyPair();
            return (keyPair, CreateSelfSigned(keyPair, "SHA256WITHRSA"));
        }

        public static (AsymmetricCipherKeyPair keyPair, X509Certificate certificate) GenerateSelfSignedEcCertificate()
        {
            var ecCurve = ECNamedCurveTable.GetByName("P-256");
            var domainParams = new ECDomainParameters(ecCurve.Curve, ecCurve.G, ecCurve.N, ecCurve.H);
            var ecGenerator = new ECKeyPairGenerator();
            ecGenerator.Init(new ECKeyGenerationParameters(domainParams, new SecureRandom()));
            var keyPair = ecGenerator.GenerateKeyPair();
            return (keyPair, CreateSelfSigned(keyPair, "SHA256WITHECDSA"));
        }

        private static X509Certificate CreateSelfSigned(AsymmetricCipherKeyPair keyPair, string signatureAlgorithm)
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

        public static (X25519PrivateKeyParameters privateX25519, X25519PublicKeyParameters publicX25519) CreateX25519KeyPair()
        {
            X25519KeyPairGenerator x25519KeyPairGenerator = new X25519KeyPairGenerator();
            x25519KeyPairGenerator.Init(new X25519KeyGenerationParameters(new SecureRandom()));
            AsymmetricCipherKeyPair keyPair = x25519KeyPairGenerator.GenerateKeyPair();
            return (keyPair.Private as X25519PrivateKeyParameters, keyPair.Public as X25519PublicKeyParameters);
        }

        public static byte[] GenerateRandom(int length)
        {
            var bytes = new byte[length];
            new SecureRandom().NextBytes(bytes);
            return bytes;
        }

        public static byte[] DeriveSharedSecretX25519(byte[] privateKey, byte[] publicKey)
        {
            if (privateKey == null) throw new ArgumentNullException(nameof(privateKey));
            if (publicKey == null) throw new ArgumentNullException(nameof(publicKey));
            if (privateKey.Length != 32) throw new ArgumentException("Private key must be 32 bytes.", nameof(privateKey));
            if (publicKey.Length != 32) throw new DtlsException(AlertDescription.IllegalParameter, "X25519 public key must be 32 bytes.");

            var priv = new X25519PrivateKeyParameters(privateKey, 0);
            var pub = new X25519PublicKeyParameters(publicKey, 0);

            var shared = new byte[32];
            priv.GenerateSecret(pub, shared, 0);

            // RFC 8446 §7.4.2: abort if the shared secret is all zeros (small-order point)
            int acc = 0;
            foreach (byte b in shared) acc |= b;
            if (acc == 0) throw new DtlsException(AlertDescription.IllegalParameter, "X25519 shared secret is zero.");

            return shared;
        }

        // ── Key schedule (RFC 8446 §7.1 with the "dtls13" label prefix of RFC 9147 §5.9) ─────────

        /// <summary>
        /// Handshake traffic keys. <paramref name="psk"/> is the resumption PSK (null for a full handshake) and
        /// <paramref name="sharedSecret"/> the (EC)DHE secret (null for psk_ke, which has none).
        /// </summary>
        public static Dtls13CryptoContext CalculateHandshakeKeys(byte[] clientRandom, byte[] helloHash, byte[] sharedSecret, Dtls13CipherSuite suite,
            byte[] psk = null)
        {
            int hashAlg = suite.HashAlgorithm;
            byte[] zeroKey = new byte[suite.HashLength];

            var earlySecret = CalculateEarlySecret(psk, suite);
            var derivedSecret = HkdfExpandLabel(new BcTlsSecret(_crypto, earlySecret), hashAlg, "derived", EmptyHash(suite), suite.HashLength).Extract();
            var handshakeSecret = new BcTlsSecret(_crypto, derivedSecret).HkdfExtract(hashAlg, new BcTlsSecret(_crypto, sharedSecret ?? zeroKey)).Extract();

            var clientSecret = HkdfExpandLabel(new BcTlsSecret(_crypto, handshakeSecret), hashAlg, "c hs traffic", helloHash, suite.HashLength).Extract();
            var serverSecret = HkdfExpandLabel(new BcTlsSecret(_crypto, handshakeSecret), hashAlg, "s hs traffic", helloHash, suite.HashLength).Extract();

            return CreateContext(clientRandom, handshakeSecret, clientSecret, serverSecret, suite, epoch: 2);
        }

        public static Dtls13CryptoContext CalculateApplicationKeys(byte[] clientRandom, byte[] handshakeHash, byte[] handshakeSecret, Dtls13CipherSuite suite)
        {
            int hashAlg = suite.HashAlgorithm;
            byte[] zeroKey = new byte[suite.HashLength];

            var derivedSecret = HkdfExpandLabel(new BcTlsSecret(_crypto, handshakeSecret), hashAlg, "derived", EmptyHash(suite), suite.HashLength).Extract();
            var masterSecret = new BcTlsSecret(_crypto, derivedSecret).HkdfExtract(hashAlg, new BcTlsSecret(_crypto, zeroKey)).Extract();

            var clientSecret = HkdfExpandLabel(new BcTlsSecret(_crypto, masterSecret), hashAlg, "c ap traffic", handshakeHash, suite.HashLength).Extract();
            var serverSecret = HkdfExpandLabel(new BcTlsSecret(_crypto, masterSecret), hashAlg, "s ap traffic", handshakeHash, suite.HashLength).Extract();

            return CreateContext(clientRandom, masterSecret, clientSecret, serverSecret, suite, epoch: 3);
        }

        /// <summary>early_secret = HKDF-Extract(0, PSK), with a zero PSK when there is none (RFC 8446 §7.1).</summary>
        public static byte[] CalculateEarlySecret(byte[] psk, Dtls13CipherSuite suite)
            => new BcTlsSecret(_crypto, new byte[suite.HashLength])
                .HkdfExtract(suite.HashAlgorithm, new BcTlsSecret(_crypto, psk ?? new byte[suite.HashLength])).Extract();

        /// <summary>
        /// PSK binder (RFC 8446 §4.2.11.2): HMAC(finished_key(Derive-Secret(early_secret, "res binder" or
        /// "ext binder", "")), Transcript-Hash(truncated ClientHello)).
        /// </summary>
        public static byte[] CalculateBinder(byte[] psk, byte[] truncatedTranscriptHash, Dtls13CipherSuite suite, bool external = false)
        {
            byte[] earlySecret = CalculateEarlySecret(psk, suite);
            byte[] binderKey = HkdfExpandLabel(new BcTlsSecret(_crypto, earlySecret), suite.HashAlgorithm, external ? "ext binder" : "res binder",
                EmptyHash(suite), suite.HashLength).Extract();
            return CalculateFinished(binderKey, truncatedTranscriptHash, suite);
        }

        /// <summary>
        /// 0-RTT keys (epoch 1, client to server only): client_early_traffic_secret =
        /// Derive-Secret(early_secret, "c e traffic", ClientHello) (RFC 8446 §7.1, RFC 9147 §6.1).
        /// </summary>
        public static Dtls13CryptoContext CalculateEarlyKeys(byte[] clientRandom, byte[] clientHelloHash, byte[] psk, Dtls13CipherSuite suite)
        {
            byte[] earlySecret = CalculateEarlySecret(psk, suite);
            byte[] clientSecret = HkdfExpandLabel(new BcTlsSecret(_crypto, earlySecret), suite.HashAlgorithm, "c e traffic", clientHelloHash, suite.HashLength).Extract();
            return CreateContext(clientRandom, earlySecret, clientSecret, clientSecret, suite, epoch: 1);
        }

        /// <summary>resumption_master_secret = Derive-Secret(master_secret, "res master", ClientHello..client Finished)</summary>
        public static byte[] CalculateResumptionMasterSecret(byte[] masterSecret, byte[] clientFinishedHash, Dtls13CipherSuite suite)
            => HkdfExpandLabel(new BcTlsSecret(_crypto, masterSecret), suite.HashAlgorithm, "res master", clientFinishedHash, suite.HashLength).Extract();

        /// <summary>The PSK of one ticket: HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce, Hash.length).</summary>
        public static byte[] CalculateResumptionPsk(byte[] resumptionMasterSecret, byte[] ticketNonce, Dtls13CipherSuite suite)
            => HkdfExpandLabel(new BcTlsSecret(_crypto, resumptionMasterSecret), suite.HashAlgorithm, "resumption", ticketNonce, suite.HashLength).Extract();

        /// <summary>exporter_master_secret = Derive-Secret(master_secret, "exp master", ClientHello..server Finished)</summary>
        public static byte[] CalculateExporterMasterSecret(byte[] masterSecret, byte[] handshakeHash, Dtls13CipherSuite suite)
        {
            return HkdfExpandLabel(new BcTlsSecret(_crypto, masterSecret), suite.HashAlgorithm, "exp master", handshakeHash, suite.HashLength).Extract();
        }

        /// <summary>
        /// RFC 8446 §7.5: TLS-Exporter(label, context, length) =
        ///   HKDF-Expand-Label(Derive-Secret(exporter_master_secret, label, ""), "exporter", Hash(context), length)
        /// An absent context is treated as empty, as TLS 1.3 does not distinguish them.
        /// </summary>
        public static byte[] ExportKeyingMaterial(byte[] exporterMasterSecret, string label, byte[] context, int length, Dtls13CipherSuite suite)
        {
            byte[] derived = HkdfExpandLabel(new BcTlsSecret(_crypto, exporterMasterSecret), suite.HashAlgorithm, label, EmptyHash(suite), suite.HashLength).Extract();

            var digest = suite.CreateDigest();
            context ??= Array.Empty<byte>();
            digest.BlockUpdate(context, 0, context.Length);
            byte[] contextHash = new byte[digest.GetDigestSize()];
            digest.DoFinal(contextHash, 0);

            return HkdfExpandLabel(new BcTlsSecret(_crypto, derived), suite.HashAlgorithm, "exporter", contextHash, length).Extract();
        }

        private static Dtls13CryptoContext CreateContext(byte[] clientRandom, byte[] secret, byte[] clientSecret, byte[] serverSecret, Dtls13CipherSuite suite, ulong epoch)
        {
            var (clientKey, clientIv, clientSnKey) = DeriveTrafficKeys(clientSecret, suite);
            var (serverKey, serverIv, serverSnKey) = DeriveTrafficKeys(serverSecret, suite);
            return new Dtls13CryptoContext(clientRandom, secret, clientSecret, serverSecret, clientKey, clientIv, serverKey, serverIv, clientSnKey, serverSnKey, suite.Id, epoch);
        }

        private static (byte[] key, byte[] iv, byte[] snKey) DeriveTrafficKeys(byte[] trafficSecret, Dtls13CipherSuite suite)
        {
            var secret = new BcTlsSecret(_crypto, trafficSecret);
            byte[] key   = HkdfExpandLabel(secret, suite.HashAlgorithm, "key", Array.Empty<byte>(), suite.KeyLength).Extract();
            byte[] iv    = HkdfExpandLabel(new BcTlsSecret(_crypto, trafficSecret), suite.HashAlgorithm, "iv", Array.Empty<byte>(), suite.IvLength).Extract();
            byte[] snKey = HkdfExpandLabel(new BcTlsSecret(_crypto, trafficSecret), suite.HashAlgorithm, "sn", Array.Empty<byte>(), suite.KeyLength).Extract();
            return (key, iv, snKey);
        }

        /// <summary>verify_data = HMAC(finished_key, transcript_hash), finished_key = HKDF-Expand-Label(base_key, "finished", "", Hash.length)</summary>
        public static byte[] CalculateFinished(byte[] baseKey, byte[] transcriptHash, Dtls13CipherSuite suite)
        {
            byte[] finishedKey = HkdfExpandLabel(new BcTlsSecret(_crypto, baseKey), suite.HashAlgorithm, "finished", Array.Empty<byte>(), suite.HashLength).Extract();
            var hmac = new HMac(suite.CreateDigest());
            hmac.Init(new KeyParameter(finishedKey));
            hmac.BlockUpdate(transcriptHash, 0, transcriptHash.Length);
            byte[] mac = new byte[hmac.GetMacSize()];
            hmac.DoFinal(mac, 0);
            return mac;
        }

        // RFC 8446 §7.2: application_traffic_secret_N+1 = HKDF-Expand-Label(application_traffic_secret_N, "traffic upd", "", Hash.length)
        // RFC 9147 §8: each KeyUpdate moves that direction to the next epoch.
        public static Dtls13CryptoContext UpdateClientTrafficSecret(Dtls13CryptoContext current)
        {
            var suite = current.Suite;
            var newClientSecret = HkdfExpandLabel(new BcTlsSecret(_crypto, current.ClientSecret), suite.HashAlgorithm, "traffic upd", Array.Empty<byte>(), suite.HashLength).Extract();
            var (key, iv, snKey) = DeriveTrafficKeys(newClientSecret, suite);

            return new Dtls13CryptoContext(
                current.ClientRandom, current.Secret,
                newClientSecret, current.ServerSecret,
                key, iv,
                current.ServerKey, current.ServerIv,
                snKey, current.ServerSnKey,
                suite.Id, current.Epoch + 1);
        }

        public static Dtls13CryptoContext UpdateServerTrafficSecret(Dtls13CryptoContext current)
        {
            var suite = current.Suite;
            var newServerSecret = HkdfExpandLabel(new BcTlsSecret(_crypto, current.ServerSecret), suite.HashAlgorithm, "traffic upd", Array.Empty<byte>(), suite.HashLength).Extract();
            var (key, iv, snKey) = DeriveTrafficKeys(newServerSecret, suite);

            return new Dtls13CryptoContext(
                current.ClientRandom, current.Secret,
                current.ClientSecret, newServerSecret,
                current.ClientKey, current.ClientIv,
                key, iv,
                current.ClientSnKey, snKey,
                suite.Id, current.Epoch + 1);
        }

        private static byte[] EmptyHash(Dtls13CipherSuite suite)
        {
            var digest = suite.CreateDigest();
            byte[] hash = new byte[digest.GetDigestSize()];
            digest.DoFinal(hash, 0);
            return hash;
        }

        // we have to duplicate the HkdfExpandLabel method because we need a different prefix for DTLS 1.3
        private readonly static byte[] Dtls13Prefix = Encoding.ASCII.GetBytes("dtls13");

        /// <exception cref="System.IO.IOException"/>
        public static TlsSecret HkdfExpandLabel(TlsSecret secret, int cryptoHashAlgorithm, string label,
            byte[] context, int length)
        {
            return HkdfExpandLabel(secret, cryptoHashAlgorithm, label.AsSpan(), context.AsSpan(), length);
        }

        /// <exception cref="System.IO.IOException"/>
        public static TlsSecret HkdfExpandLabel(TlsSecret secret, int cryptoHashAlgorithm, ReadOnlySpan<char> label,
            ReadOnlySpan<byte> context, int length)
        {
            int labelLength = label.Length;
            if (labelLength < 1)
                throw new TlsFatalAlert(Org.BouncyCastle.Tls.AlertDescription.internal_error);

            int contextLength = context.Length;
            int expandedLabelLength = Dtls13Prefix.Length + labelLength;

            int hkdfLabelLength = 2 + (1 + expandedLabelLength) + (1 + contextLength);
            Span<byte> hkdfLabel = hkdfLabelLength <= 512
                ? stackalloc byte[hkdfLabelLength]
                : new byte[hkdfLabelLength];

            // uint16 length
            TlsUtilities.CheckUint16(length);
            TlsUtilities.WriteUint16(length, hkdfLabel);

            // opaque label<7..255>
            TlsUtilities.CheckUint8(expandedLabelLength);
            TlsUtilities.WriteUint8(expandedLabelLength, hkdfLabel[2..]);
            Dtls13Prefix.CopyTo(hkdfLabel[3..]);
            int labelPos = 2 + (1 + Dtls13Prefix.Length);
            for (int i = 0; i < labelLength; ++i)
                hkdfLabel[labelPos + i] = (byte)label[i];

            // context
            TlsUtilities.WriteOpaque8(context, hkdfLabel.Slice(2 + (1 + expandedLabelLength)));

            return secret.HkdfExpand(cryptoHashAlgorithm, hkdfLabel, length);
        }
    }
}
