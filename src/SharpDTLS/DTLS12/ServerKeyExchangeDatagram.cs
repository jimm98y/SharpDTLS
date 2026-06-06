using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace SharpDTLS.DTLS12
{
    public class ServerKeyExchangeDatagram : IDatagram
    {
        public byte[] KeyExchangeData { get; set; } = new byte[0];
        public int SequenceNumber { get; set; } = 0;
        public byte[] Bytes { get; private set; }

        public ServerKeyExchangeDatagram()
        {
        }

        public ServerKeyExchangeDatagram(byte[] keyExchangeData)
        {
            KeyExchangeData = keyExchangeData ?? new byte[0];
        }

        public void FromBytes(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            if (bytes.Length < 13) throw new ArgumentException("Buffer too small for ServerKeyExchange.");

            Bytes = bytes.ToArray();

            if (bytes[0] != 0x0c) throw new InvalidDataException("Not a ServerKeyExchange handshake message.");

            int length = (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
            SequenceNumber = (bytes[4] << 8) | bytes[5];

            int pos = 12;
            if (bytes.Length > pos)
            {
                KeyExchangeData = new byte[length];
                Buffer.BlockCopy(bytes, pos, KeyExchangeData, 0, Math.Min(length, bytes.Length - pos));
            }
        }

        public byte[] ToBytes()
        {
            byte[] data = new byte[4096];

            data[0] = 0x0c; // ServerKeyExchange

            int keyLen = KeyExchangeData?.Length ?? 0;
            int length = keyLen;
            data[1] = (byte)((length >> 16) & 0xFF);
            data[2] = (byte)((length >> 8) & 0xFF);
            data[3] = (byte)(length & 0xFF);

            data[4] = (byte)((SequenceNumber >> 8) & 0xFF);
            data[5] = (byte)(SequenceNumber & 0xFF);

            data[6] = 0; data[7] = 0; data[8] = 0;
            data[9] = 0; data[10] = 0; data[11] = 0;

            int pos = 12;

            if (keyLen > 0)
            {
                Buffer.BlockCopy(KeyExchangeData, 0, data, pos, keyLen);
                pos += keyLen;
            }

            // record type
            data[pos++] = 0x16;

            // update fragment length
            int fragmentLength = length;
            data[9] = (byte)((fragmentLength >> 16) & 0xFF);
            data[10] = (byte)((fragmentLength >> 8) & 0xFF);
            data[11] = (byte)(fragmentLength & 0xFF);

            Bytes = data.Take(pos).ToArray();
            return Bytes;
        }
    }
}
