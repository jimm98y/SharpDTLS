using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Linq;

namespace Dtls13Test.Messages
{
    public class ClientEncryptedDatagram : IDatagram
    {
        private readonly Dtls13CryptoContext _cryptoContext;
        public IDatagram Datagram { get; set; }
        public ushort RecordNumber { get; set; }
        public int Epoch { get; set; } = 2;
        public byte[] Bytes { get; set; }

        public ClientEncryptedDatagram(Dtls13CryptoContext cryptoContext)
        {
            this._cryptoContext = cryptoContext ?? throw new ArgumentNullException(nameof(cryptoContext));
        }

        public ClientEncryptedDatagram(Dtls13CryptoContext cryptoContext, IDatagram datagram) : this(cryptoContext)
        {
            this.Datagram = datagram;
        }

        public void FromBytes(byte[] encrypted)
        {
            if ((encrypted[0] & 0x20) != 0x20)
                throw new Exception("Wrong datagram");

            Bytes = encrypted.ToArray();

            bool connectionIdPresent = (encrypted[0] & 0x10) == 0x10;
            bool is16bitLength = (encrypted[0] & 0x08) == 0x08;
            bool isLengthPresent = (encrypted[0] & 0x04) == 0x04;
            this.Epoch = (byte)(encrypted[0] & 0x03);

            ushort recordLength = (ushort)((encrypted[3] << 8) | encrypted[4]);

            byte[] headerEncryption = GetHeaderEncryption(encrypted);

            this.RecordNumber = (ushort)(((encrypted[1] ^ headerEncryption[0]) << 8) | (encrypted[2] ^ headerEncryption[1]));
            encrypted[1] = (byte)((this.RecordNumber >> 8) & 0xFF);
            encrypted[2] = (byte)(this.RecordNumber & 0xFF);

            byte[] iv = new byte[_cryptoContext.ClientIv.Length];
            Buffer.BlockCopy(_cryptoContext.ClientIv, 0, iv, 0, _cryptoContext.ClientIv.Length);
            iv[iv.Length - 8] ^= (byte)((_cryptoContext.ClientKeyUseCounter >> 56) & 0xFF);
            iv[iv.Length - 7] ^= (byte)((_cryptoContext.ClientKeyUseCounter >> 48) & 0xFF);
            iv[iv.Length - 6] ^= (byte)((_cryptoContext.ClientKeyUseCounter >> 40) & 0xFF);
            iv[iv.Length - 5] ^= (byte)((_cryptoContext.ClientKeyUseCounter >> 32) & 0xFF);
            iv[iv.Length - 4] ^= (byte)((_cryptoContext.ClientKeyUseCounter >> 24) & 0xFF);
            iv[iv.Length - 3] ^= (byte)((_cryptoContext.ClientKeyUseCounter >> 16) & 0xFF);
            iv[iv.Length - 2] ^= (byte)((_cryptoContext.ClientKeyUseCounter >> 8) & 0xFF);
            iv[iv.Length - 1] ^= (byte)(_cryptoContext.ClientKeyUseCounter & 0xFF);

            Encrypt(_cryptoContext.AeadEncryptEngine, false, encrypted, 5, encrypted.Length, iv, new KeyParameter(_cryptoContext.ClientKey), 16, encrypted.Take(5).ToArray());

            byte[] plaintext = encrypted.Skip(5).Take(encrypted.Length - 5 - 16).ToArray();

            if (plaintext[plaintext.Length - 1] == 0x16)
            {
                this.Datagram = plaintext[0] switch
                {
                    0x14 => new FinishedDatagram(),
                    _ => throw new Exception("Unknown datagram type")
                };
            }
            else if (plaintext[plaintext.Length - 1] == 0x1a)
            {
                this.Datagram = new AcknowledgementDatagram();
            }
            else if (plaintext[plaintext.Length - 1] == 0x17)
            {
                this.Datagram = new ApplicationDataDatagram();
            }
            else
            {
                throw new NotSupportedException();
            }

            this.Datagram.FromBytes(plaintext);
        }

        public byte[] ToBytes()
        {
            byte[] encrypted = new byte[2048];
            bool connectionIdPresent = false; // Assume Connection ID is included for this example
            bool is16bitLength = true;
            bool isLengthPresent = true;

            encrypted[0] = (byte)(0x20 | (connectionIdPresent ? 0x10 : 0x00) | (is16bitLength ? 0x08 : 0x00) | (isLengthPresent ? 0x04 : 0x00) | (this.Epoch & 0x03));

            byte[] plaintext = Datagram.ToBytes();
            ushort recordLength = (ushort)(plaintext.Length + 16);

            encrypted[1] = (byte)((this.RecordNumber >> 8) & 0xFF);
            encrypted[2] = (byte)(this.RecordNumber & 0xFF);

            encrypted[3] = (byte)((recordLength >> 8) & 0xFF);
            encrypted[4] = (byte)(recordLength & 0xFF);

            // encrypted data
            Buffer.BlockCopy(plaintext, 0, encrypted, 5, plaintext.Length);

            byte[] iv = new byte[_cryptoContext.ClientIv.Length];
            Buffer.BlockCopy(_cryptoContext.ClientIv, 0, iv, 0, _cryptoContext.ClientIv.Length);
            iv[iv.Length - 1] ^= (byte)((_cryptoContext.ClientKeyUseCounter >> 24) & 0xFF);
            iv[iv.Length - 1] ^= (byte)((_cryptoContext.ClientKeyUseCounter >> 16) & 0xFF);
            iv[iv.Length - 1] ^= (byte)((_cryptoContext.ClientKeyUseCounter >> 8) & 0xFF);
            iv[iv.Length - 1] ^= (byte)(_cryptoContext.ClientKeyUseCounter & 0xFF);

            Encrypt(_cryptoContext.AeadDecryptEngine, true, encrypted, 5, 5 + plaintext.Length, iv, new KeyParameter(_cryptoContext.ClientKey), 16, encrypted.Take(5).ToArray());

            // encrypt record number
            byte[] headerEncryption = GetHeaderEncryption(encrypted);
            encrypted[1] = (byte)(((this.RecordNumber >> 8) & 0xFF) ^ headerEncryption[0]);
            encrypted[2] = (byte)((this.RecordNumber & 0xFF) ^ headerEncryption[1]);

            Bytes = encrypted.Take(5 + plaintext.Length + 16).ToArray();

            return Bytes;
        }

        private byte[] GetHeaderEncryption(byte[] encrypted)
        {
            byte[] sample = new byte[16];
            Buffer.BlockCopy(encrypted, 5, sample, 0, 16);
            _cryptoContext.AesEngine.Init(true, new KeyParameter(_cryptoContext.ClientSnKey));
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
