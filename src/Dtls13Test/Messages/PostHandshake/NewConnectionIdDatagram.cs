using System;
using System.Collections.Generic;
using System.Text;

namespace Dtls13Test.Messages
{
    public class NewConnectionIdDatagram : IDatagram
    {
        public byte[] Bytes => throw new NotImplementedException();

        public void FromBytes(byte[] bytes)
        {
            throw new NotImplementedException();
        }

        public byte[] ToBytes()
        {
            throw new NotImplementedException();
        }
    }
}
