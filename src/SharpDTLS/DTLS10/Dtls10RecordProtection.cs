using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Security.Cryptography;

namespace SharpDTLS.DTLS10
{
    /// <summary>
    /// AES-CBC + HMAC-SHA1 record decryption (MAC-then-encrypt, explicit IV; RFC 4346 §6.2.3.2).
    /// </summary>
    internal static class Dtls10RecordProtection
    {
        private const int BlockSize = 16;
        private const int MacLength = 20;

        /// <summary>
        /// Decrypts a CBC record and verifies padding and MAC. Every failure takes the same path and
        /// throws <see cref="DtlsRecordDiscardedException"/> (invalid records are silently discarded in DTLS),
        /// and padding is checked in constant time so the result does not act as a padding oracle.
        /// Residual MAC-length timing (Lucky13) is not fully eliminated.
        /// </summary>
        public static byte[] Open(byte[] record, byte[] key, byte[] macKey, ushort epoch, ulong sequenceNumber, byte contentType)
        {
            int recordLength = (record[11] << 8) | record[12];
            int ciphertextLength = recordLength - BlockSize;
            if (record.Length != 13 + recordLength || ciphertextLength < MacLength + 1 || ciphertextLength % BlockSize != 0)
                throw new DtlsRecordDiscardedException("Invalid CBC record length");

            byte[] iv = new byte[BlockSize];
            Buffer.BlockCopy(record, 13, iv, 0, BlockSize);

            var cipher = new CbcBlockCipher(new AesEngine());
            cipher.Init(false, new ParametersWithIV(new KeyParameter(key), iv));
            byte[] plaintext = new byte[ciphertextLength];
            for (int i = 0; i < ciphertextLength; i += BlockSize)
                cipher.ProcessBlock(record, 13 + BlockSize + i, plaintext, i);

            // Padding: padLen + 1 bytes, all equal to padLen. Examine the maximum possible 256 bytes
            // (or the whole plaintext) regardless of the claimed length.
            int padLength = plaintext[plaintext.Length - 1];
            int good = (padLength + 1 + MacLength <= plaintext.Length) ? 1 : 0;
            int toCheck = Math.Min(256, plaintext.Length);
            int mismatch = 0;
            for (int i = 1; i <= toCheck; i++)
            {
                // inside the padding when i <= padLength + 1
                int inPadding = ((padLength + 1 - i) >> 31) + 1; // 1 when i <= padLength + 1, else 0
                mismatch |= (plaintext[plaintext.Length - i] ^ padLength) & (-inPadding);
            }
            good &= mismatch == 0 ? 1 : 0;

            // With bad padding, MAC as if there were no padding so the work done is similar.
            int effectivePad = good == 1 ? padLength + 1 : 0;
            int fragmentLength = plaintext.Length - MacLength - effectivePad;

            byte[] fragment = new byte[fragmentLength];
            Buffer.BlockCopy(plaintext, 0, fragment, 0, fragmentLength);
            byte[] receivedMac = new byte[MacLength];
            Buffer.BlockCopy(plaintext, fragmentLength, receivedMac, 0, MacLength);

            byte[] expectedMac = Messages.ServerEncryptedDatagram.ComputeMac(macKey, epoch, sequenceNumber, contentType, fragment);
            good &= CryptographicOperations.FixedTimeEquals(receivedMac, expectedMac) ? 1 : 0;

            if (good != 1)
                throw new DtlsRecordDiscardedException("Record failed authentication");

            return fragment;
        }
    }
}
