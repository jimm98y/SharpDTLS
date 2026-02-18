using System;
using System.Collections.Generic;
using System.Text;

namespace Dtls13Test.Messages
{
    public class ServerEncryptedExtensionsDatagram : IDatagram
    {
        public void FromBytes(byte[] bytes)
        {
            throw new NotImplementedException();
        }

        public byte[] ToBytes()
        {
            byte[] encrypted = new byte[2048];
            bool connectionIdPresent = false; // Assume Connection ID is included for this example
            bool is16bitLength = true;
            bool isLengthPresent = true;
            int epochLSB = 2;
            encrypted[0] = (byte)(0x20 | (connectionIdPresent ? 0x10 : 0x00) | (is16bitLength ? 0x08 : 0x00) | (isLengthPresent ? 0x04 : 0x00) | (epochLSB & 0x03));

            ushort recordNumber = 0;
            ushort recordLength = 0;

            // TODO: encrypt
            encrypted[1] = (byte)((recordNumber >> 8) & 0xFF);         
            encrypted[2] = (byte)(recordNumber & 0xFF);

            encrypted[3] = (byte)((recordLength >> 8) & 0xFF);
            encrypted[4] = (byte)(recordLength & 0xFF);

            // encrypted data

            // auth tag

            throw new NotImplementedException();
        }
    }
}
