using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using SharpDTLS.DTLS10.Messages;
using SharpDTLS.DTLS12;
using SharpSRTP.UDP;
using System;
using System.Linq;
using System.Net;

namespace SharpDTLS.DTLS10
{
    public class Dtls10DataReceivedEventArgs : EventArgs
    {
        public Dtls10DataReceivedEventArgs(EndPoint remoteEndPoint, byte[] data)
        {
            RemoteEndPoint = remoteEndPoint;
            Data = data;
        }

        public EndPoint RemoteEndPoint { get; }
        public byte[] Data { get; }
    }

    /// <summary>
    /// DTLS 1.0 server (RFC 4347): the DTLS 1.0/1.2 engine restricted to DTLS 1.0.
    /// </summary>
    public class Dtls10Server : Dtls12ServerBase
    {
        // ECDHE CBC suites usable with DTLS 1.0, by certificate key type.
        public static readonly ushort[] EcdsaCipherSuites = SharpDTLS.CipherSuites.All.Where(s => s.ServerCertificateType == CertificateKeyType.Ecdsa && s.IsUsableWith(DtlsVersion.Dtls10)).Select(s => s.Id).ToArray();
        public static readonly ushort[] RsaCipherSuites = SharpDTLS.CipherSuites.All.Where(s => s.ServerCertificateType == CertificateKeyType.Rsa && s.IsUsableWith(DtlsVersion.Dtls10)).Select(s => s.Id).ToArray();

        public event EventHandler<EventArgs> HandshakeFinished;
        public event EventHandler<AlertDatagram> AlertReceived;
        public event EventHandler<Dtls10DataReceivedEventArgs> ApplicationDataReceived;

        public Dtls10Server(IServerTransport serverTransport)
            : this(serverTransport, Dtls10CryptoUtils.GenerateSelfSignedCertificate())
        {
        }

        public Dtls10Server(IServerTransport serverTransport, AsymmetricCipherKeyPair keyPair, X509Certificate certificate)
            : base(serverTransport, keyPair, certificate, DtlsVersion.Dtls10)
        {
        }

        private Dtls10Server(IServerTransport serverTransport, (AsymmetricCipherKeyPair keyPair, X509Certificate certificate) credentials)
            : this(serverTransport, credentials.keyPair, credentials.certificate)
        {
        }

        protected override void OnConnectionEstablished(Dtls12ServerConnection connection)
            => HandshakeFinished?.Invoke(this, EventArgs.Empty);

        protected override void OnApplicationData(Dtls12ServerConnection connection, byte[] data)
            => ApplicationDataReceived?.Invoke(this, new Dtls10DataReceivedEventArgs(connection.RemoteEndPoint, data));

        protected override void OnAlert(Dtls12ServerConnection connection, AlertDescription description)
            => AlertReceived?.Invoke(this, new AlertDatagram(description == AlertDescription.CloseNotify ? (byte)1 : (byte)2, (byte)description));
    }
}
