using System;
using System.Collections.Generic;

namespace SharpDTLS
{
    /// <summary>
    /// Splits a received UDP datagram into individual DTLS records. A single datagram may carry
    /// several records (RFC 6347 §4.1.1, RFC 9147 §4.3).
    /// </summary>
    public static class DtlsRecordSplitter
    {
        private const int PlaintextHeaderLength = 13;
        private const byte Tls12Cid = 25;

        /// <param name="connectionIdLength">
        /// Length of the connection IDs the receiver expects: in DTLS 1.3 unified headers and in DTLS 1.2 tls12_cid
        /// records (RFC 9146), whose CID sits between the sequence number and the length.
        /// </param>
        public static List<byte[]> Split(byte[] datagram, int connectionIdLength = 0)
        {
            var records = new List<byte[]>();
            int pos = 0;

            while (pos < datagram.Length)
            {
                byte first = datagram[pos];
                int recordLength;

                if ((first & 0xE0) == 0x20)
                {
                    // DTLS 1.3 unified header: 0 0 1 C S L E E
                    bool hasCid    = (first & 0x10) != 0;
                    bool seq16     = (first & 0x08) != 0;
                    bool hasLength = (first & 0x04) != 0;

                    int headerLength = 1 + (hasCid ? connectionIdLength : 0) + (seq16 ? 2 : 1) + (hasLength ? 2 : 0);
                    if (pos + headerLength > datagram.Length)
                        break; // truncated, drop the rest

                    if (hasLength)
                    {
                        int lenOffset = pos + headerLength - 2;
                        recordLength = headerLength + ((datagram[lenOffset] << 8) | datagram[lenOffset + 1]);
                    }
                    else
                    {
                        // without a length the record extends to the end of the datagram
                        recordLength = datagram.Length - pos;
                    }
                }
                else
                {
                    int cidLength = first == Tls12Cid ? connectionIdLength : 0;
                    if (pos + PlaintextHeaderLength + cidLength > datagram.Length)
                        break;
                    recordLength = PlaintextHeaderLength + cidLength + ((datagram[pos + 11 + cidLength] << 8) | datagram[pos + 12 + cidLength]);
                }

                if (recordLength <= 0 || pos + recordLength > datagram.Length)
                    break; // malformed: discard the remainder of the datagram (RFC 9147 §4.5.2)

                byte[] record = new byte[recordLength];
                Buffer.BlockCopy(datagram, pos, record, 0, recordLength);
                records.Add(record);
                pos += recordLength;
            }

            return records;
        }
    }
}
