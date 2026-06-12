using System;
using System.Collections.Generic;

namespace SharpDTLS
{
    public static class HandshakeFragmenter
    {
        /// <summary>
        /// Splits an unencrypted DTLS record (ClientHello / ServerHello format) into per-MTU fragments.
        /// Each returned byte[] is a standalone DTLS record with updated record sequence number,
        /// fragment_offset, and fragment_length. Returns a single-element list when the record fits.
        /// </summary>
        /// <param name="record">Full DTLS record as returned by ClientHelloDatagram.ToBytes() etc.</param>
        /// <param name="mtu">Maximum total datagram size in bytes.</param>
        /// <param name="recordSeq">Record sequence counter; incremented for each emitted record.</param>
        public static List<byte[]> FragmentUnencryptedRecord(byte[] record, int mtu, ref int recordSeq)
        {
            // Unencrypted DTLS handshake record layout:
            //  [0]      record type (0x16)
            //  [1-2]    version
            //  [3-4]    epoch
            //  [5-10]   record sequence number (6 bytes, big-endian)
            //  [11-12]  record length (2 bytes)
            //  [13]     HS type
            //  [14-16]  HS total body length (3 bytes)
            //  [17-18]  msg_seq (2 bytes)
            //  [19-21]  fragment_offset (3 bytes)
            //  [22-24]  fragment_length (3 bytes)
            //  [25+]    HS body

            const int RecordHeaderSize = 13;
            const int HsHeaderSize = 12;
            int maxBodyPerFragment = mtu - RecordHeaderSize - HsHeaderSize;

            int totalBodyLength = (record[14] << 16) | (record[15] << 8) | record[16];

            if (totalBodyLength <= maxBodyPerFragment)
            {
                long s = recordSeq++;
                record[5] = (byte)((s >> 40) & 0xFF);
                record[6] = (byte)((s >> 32) & 0xFF);
                record[7] = (byte)((s >> 24) & 0xFF);
                record[8] = (byte)((s >> 16) & 0xFF);
                record[9] = (byte)((s >> 8) & 0xFF);
                record[10] = (byte)(s & 0xFF);
                return new List<byte[]> { record };
            }

            var result = new List<byte[]>();
            for (int offset = 0; offset < totalBodyLength; offset += maxBodyPerFragment)
            {
                int chunkSize = Math.Min(maxBodyPerFragment, totalBodyLength - offset);
                byte[] fragment = new byte[RecordHeaderSize + HsHeaderSize + chunkSize];

                // Record header
                fragment[0] = record[0]; // record type
                fragment[1] = record[1]; // version hi
                fragment[2] = record[2]; // version lo
                fragment[3] = record[3]; // epoch hi
                fragment[4] = record[4]; // epoch lo
                long seq = recordSeq++;
                fragment[5] = (byte)((seq >> 40) & 0xFF);
                fragment[6] = (byte)((seq >> 32) & 0xFF);
                fragment[7] = (byte)((seq >> 24) & 0xFF);
                fragment[8] = (byte)((seq >> 16) & 0xFF);
                fragment[9] = (byte)((seq >> 8) & 0xFF);
                fragment[10] = (byte)(seq & 0xFF);
                int recordLength = HsHeaderSize + chunkSize;
                fragment[11] = (byte)((recordLength >> 8) & 0xFF);
                fragment[12] = (byte)(recordLength & 0xFF);

                // HS header
                fragment[13] = record[13]; // HS type
                fragment[14] = record[14]; // total body length (unchanged)
                fragment[15] = record[15];
                fragment[16] = record[16];
                fragment[17] = record[17]; // msg_seq (unchanged)
                fragment[18] = record[18];
                fragment[19] = (byte)((offset >> 16) & 0xFF); // fragment_offset
                fragment[20] = (byte)((offset >> 8) & 0xFF);
                fragment[21] = (byte)(offset & 0xFF);
                fragment[22] = (byte)((chunkSize >> 16) & 0xFF); // fragment_length
                fragment[23] = (byte)((chunkSize >> 8) & 0xFF);
                fragment[24] = (byte)(chunkSize & 0xFF);

                Buffer.BlockCopy(record, 25 + offset, fragment, 25, chunkSize);
                result.Add(fragment);
            }
            return result;
        }

        /// <summary>
        /// Splits an encrypted handshake plaintext into fragments no larger than maxBodySize HS body bytes.
        /// Input is the output of IDatagram.ToBytes() for datagrams like CertificateDatagram.
        /// Each returned byte[] is a complete plaintext ready to be independently encrypted as a DTLS record.
        /// Returns the original plaintext unchanged when it fits in a single record.
        /// </summary>
        /// <param name="plaintext">Plaintext bytes as returned by an encrypted datagram's ToBytes().</param>
        /// <param name="maxBodySize">Maximum number of HS body bytes per fragment.</param>
        public static IEnumerable<byte[]> FragmentHandshakePlaintext(byte[] plaintext, int maxBodySize)
        {
            // Encrypted handshake plaintext layout:
            //  [0]        HS type
            //  [1-3]      HS total body length (3 bytes)
            //  [4-5]      msg_seq (2 bytes)
            //  [6-8]      fragment_offset (3 bytes)
            //  [9-11]     fragment_length (3 bytes)
            //  [12 .. 12+totalLength-1]  HS body
            //  [12+totalLength]          content type (e.g. 0x16 for handshake)

            const int HsHeaderSize = 12;
            int totalBodyLength = (plaintext[1] << 16) | (plaintext[2] << 8) | plaintext[3];
            byte contentType = plaintext[HsHeaderSize + totalBodyLength];

            if (totalBodyLength <= maxBodySize)
            {
                yield return plaintext;
                yield break;
            }

            for (int offset = 0; offset < totalBodyLength; offset += maxBodySize)
            {
                int chunkSize = Math.Min(maxBodySize, totalBodyLength - offset);
                byte[] fragment = new byte[HsHeaderSize + chunkSize + 1];

                fragment[0] = plaintext[0]; // HS type
                fragment[1] = plaintext[1]; // total body length (unchanged)
                fragment[2] = plaintext[2];
                fragment[3] = plaintext[3];
                fragment[4] = plaintext[4]; // msg_seq (unchanged)
                fragment[5] = plaintext[5];
                fragment[6] = (byte)((offset >> 16) & 0xFF); // fragment_offset
                fragment[7] = (byte)((offset >> 8) & 0xFF);
                fragment[8] = (byte)(offset & 0xFF);
                fragment[9] = (byte)((chunkSize >> 16) & 0xFF); // fragment_length
                fragment[10] = (byte)((chunkSize >> 8) & 0xFF);
                fragment[11] = (byte)(chunkSize & 0xFF);

                Buffer.BlockCopy(plaintext, HsHeaderSize + offset, fragment, HsHeaderSize, chunkSize);
                fragment[HsHeaderSize + chunkSize] = contentType;

                yield return fragment;
            }
        }
    }

    /// <summary>
    /// Wraps a pre-built plaintext byte array as an IDatagram so it can be passed to
    /// ServerEncryptedDatagram / ClientEncryptedDatagram without re-serialisation.
    /// Used internally for fragmented sends.
    /// </summary>
    internal sealed class RawPlaintextDatagram : IDatagram
    {
        public byte[] Bytes { get; }
        public RawPlaintextDatagram(byte[] bytes) => Bytes = bytes;
        public void FromBytes(byte[] bytes) => throw new NotSupportedException();
        public byte[] ToBytes() => Bytes;
    }
}
