using System;

namespace Dtls13Test.Messages
{
    public class CertificateRequestDatagram : IDatagram
    {
        public byte[] Bytes { get; private set; }

        public CertificateRequestDatagram()
        {  }

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
