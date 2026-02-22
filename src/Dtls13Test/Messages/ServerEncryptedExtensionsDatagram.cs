using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace Dtls13Test.Messages
{
    public class ServerEncryptedExtensionsDatagram : IDatagram
    {
        private readonly Dtls13CryptoContext _cryptoContext;
        public IDatagram Datagram { get; set; }
        public ushort RecordNumber { get; private set; }

        public ServerEncryptedExtensionsDatagram(Dtls13CryptoContext cryptoContext, IDatagram datagram)
        {
            this._cryptoContext = cryptoContext ?? throw new ArgumentNullException(nameof(cryptoContext));
            this.Datagram = datagram;
        }

        public void FromBytes(byte[] encrypted)
        {
            if ((encrypted[0] & 0x20) != 0x20)
                throw new Exception("Wrong datagram");

            bool connectionIdPresent = (encrypted[0] & 0x10) == 0x10;
            bool is16bitLength = (encrypted[0] & 0x08) == 0x08;
            bool isLengthPresent = (encrypted[0] & 0x04) == 0x04;
            int epochLSB = encrypted[0] & 0x03;

            ushort recordLength = (ushort)((encrypted[3] << 8) | encrypted[4]);

            byte[] headerEncryption = GetHeaderEncryption(encrypted);

            this.RecordNumber = (ushort)(((encrypted[1] ^ headerEncryption[0]) << 8) | (encrypted[2] ^ headerEncryption[1]));
            encrypted[1] = (byte)((this.RecordNumber >> 8) & 0xFF);
            encrypted[2] = (byte)(this.RecordNumber & 0xFF);

            byte[] iv = new byte[_cryptoContext.ServerIv.Length];
            Buffer.BlockCopy(_cryptoContext.ServerIv, 0, iv, 0, _cryptoContext.ServerIv.Length);
            iv[iv.Length - 1] ^= (byte)((_cryptoContext.ServerKeyUseCounter >> 24) & 0xFF);
            iv[iv.Length - 1] ^= (byte)((_cryptoContext.ServerKeyUseCounter >> 16) & 0xFF);
            iv[iv.Length - 1] ^= (byte)((_cryptoContext.ServerKeyUseCounter >> 8) & 0xFF);
            iv[iv.Length - 1] ^= (byte)(_cryptoContext.ServerKeyUseCounter & 0xFF);

            Encrypt(_cryptoContext.AeadEncryptEngine, false, encrypted, 5, encrypted.Length, iv, new KeyParameter(_cryptoContext.ServerKey), 16, encrypted.Take(5).ToArray());

            byte[] plaintext = encrypted.Skip(5).Take(encrypted.Length - 5 - 16).ToArray();

            this.Datagram = plaintext[0] switch
            {
                0x08 => new ServerExtensionsDatagram(),
                0x0b => new ServerCertificateDatagram(),
                0x0f => new ServerCertVerifyDatagram(),
                _ => throw new Exception("Unknown datagram type")
            };

            this.Datagram.FromBytes(plaintext);
        }

        public byte[] ToBytes()
        {
            byte[] encrypted = new byte[2048];
            bool connectionIdPresent = false; // Assume Connection ID is included for this example
            bool is16bitLength = true;
            bool isLengthPresent = true;
            int epochLSB = 2;
            encrypted[0] = (byte)(0x20 | (connectionIdPresent ? 0x10 : 0x00) | (is16bitLength ? 0x08 : 0x00) | (isLengthPresent ? 0x04 : 0x00) | (epochLSB & 0x03));

            byte[] plaintext = Datagram.ToBytes();
            ushort recordLength = (ushort)(plaintext.Length + 16);

            encrypted[1] = (byte)((this.RecordNumber >> 8) & 0xFF);         
            encrypted[2] = (byte)(this.RecordNumber & 0xFF);

            encrypted[3] = (byte)((recordLength >> 8) & 0xFF);
            encrypted[4] = (byte)(recordLength & 0xFF);

            // encrypted data
            Buffer.BlockCopy(plaintext, 0, encrypted, 5, plaintext.Length);

            byte[] iv = new byte[_cryptoContext.ServerIv.Length];
            Buffer.BlockCopy(_cryptoContext.ServerIv, 0, iv, 0, _cryptoContext.ServerIv.Length);
            iv[iv.Length - 1] ^= (byte)((_cryptoContext.ServerKeyUseCounter >> 24) & 0xFF);
            iv[iv.Length - 1] ^= (byte)((_cryptoContext.ServerKeyUseCounter >> 16) & 0xFF);
            iv[iv.Length - 1] ^= (byte)((_cryptoContext.ServerKeyUseCounter >> 8) & 0xFF);
            iv[iv.Length - 1] ^= (byte)(_cryptoContext.ServerKeyUseCounter & 0xFF);

            Encrypt(_cryptoContext.AeadDecryptEngine, true, encrypted, 5, 5 + plaintext.Length, iv, new KeyParameter(_cryptoContext.ServerKey), 16, encrypted.Take(5).ToArray());

            // encrypt record number
            byte[] headerEncryption = GetHeaderEncryption(encrypted);
            encrypted[1] = (byte)(((this.RecordNumber >> 8) & 0xFF) ^ headerEncryption[0]);
            encrypted[2] = (byte)((this.RecordNumber & 0xFF) ^ headerEncryption[1]);

            return encrypted.Take(5 + plaintext.Length + 16).ToArray();
        }

        private byte[] GetHeaderEncryption(byte[] encrypted)
        {
            byte[] sample = new byte[16];
            Buffer.BlockCopy(encrypted, 5, sample, 0, 16);
            _cryptoContext.AesEngine.Init(true, new KeyParameter(_cryptoContext.ServerSnKey));
            _cryptoContext.AesEngine.ProcessBlock(sample, 0, sample, 0);
            return sample;
        }

        public static void Encrypt(IAeadBlockCipher engine, bool encrypt, byte[] payload, int offset, int length, byte[] iv, KeyParameter K_e, int N_tag, byte[] associatedData)
        {
            int payloadSize = length - offset;

            var parameters = new AeadParameters(K_e, N_tag << 3, iv, associatedData);
            engine.Init(encrypt, parameters);

            int len = engine.ProcessBytes(payload, offset, payloadSize, payload, offset);

            // throws when the MAC fails to match
            engine.DoFinal(payload, offset + len);
        }
    }
}
