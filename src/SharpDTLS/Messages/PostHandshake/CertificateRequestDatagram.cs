using System;

namespace SharpDTLS.Messages
{
    public class CertificateRequestDatagram : IDatagram
    {
        public byte[] Bytes { get; private set; }

        public CertificateRequestDatagram()
        {
            throw new NotImplementedException();
        }

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
