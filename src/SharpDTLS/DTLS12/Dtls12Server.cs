using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using SharpDTLS.DTLS12.Messages;
using SharpSRTP.UDP;
using System;
using System.Linq;
using System.Net;

namespace SharpDTLS.DTLS12
{
    public class Dtls12DataReceivedEventArgs : EventArgs
    {
        public Dtls12DataReceivedEventArgs(EndPoint remoteEndPoint, byte[] data)
        {
            RemoteEndPoint = remoteEndPoint;
            Data = data;
        }

        public EndPoint RemoteEndPoint { get; }
        public byte[] Data { get; }
    }

    /// <summary>
    /// DTLS 1.2 server. Set <see cref="Dtls12ServerBase.MinimumVersion"/> to <see cref="DtlsVersion.Dtls10"/>
    /// to also accept DTLS 1.0 clients.
    /// </summary>
    public class Dtls12Server : Dtls12ServerBase
    {
        // ECDHE suites by certificate key type, in server preference order.
        public static readonly ushort[] EcdsaCipherSuites = SharpDTLS.CipherSuites.All.Where(s => s.ServerCertificateType == CertificateKeyType.Ecdsa).Select(s => s.Id).ToArray();
        public static readonly ushort[] RsaCipherSuites = SharpDTLS.CipherSuites.All.Where(s => s.ServerCertificateType == CertificateKeyType.Rsa).Select(s => s.Id).ToArray();

        public event EventHandler<EventArgs> HandshakeFinished;
        public event EventHandler<AlertDatagram> AlertReceived;
        public event EventHandler<Dtls12DataReceivedEventArgs> ApplicationDataReceived;

        public Dtls12Server(IServerTransport serverTransport)
            : this(serverTransport, Dtls12CryptoUtils.GenerateSelfSignedCertificate())
        {
        }

        public Dtls12Server(IServerTransport serverTransport, AsymmetricCipherKeyPair keyPair, X509Certificate certificate)
            : base(serverTransport, keyPair, certificate, DtlsVersion.Dtls12)
        {
        }

        private Dtls12Server(IServerTransport serverTransport, (AsymmetricCipherKeyPair keyPair, X509Certificate certificate) credentials)
            : this(serverTransport, credentials.keyPair, credentials.certificate)
        {
        }

        protected override void OnConnectionEstablished(Tls12ServerConnection connection)
            => HandshakeFinished?.Invoke(this, EventArgs.Empty);

        protected override void OnApplicationData(Tls12ServerConnection connection, byte[] data)
            => ApplicationDataReceived?.Invoke(this, new Dtls12DataReceivedEventArgs(connection.RemoteEndPoint, data));

        protected override void OnAlert(Tls12ServerConnection connection, AlertDescription description)
            => AlertReceived?.Invoke(this, new AlertDatagram(description == AlertDescription.CloseNotify ? (byte)1 : (byte)2, (byte)description));

    }
}
