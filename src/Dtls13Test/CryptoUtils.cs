using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Dtls13Test
{
    public static class CryptoUtils
    {
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
    }
}
