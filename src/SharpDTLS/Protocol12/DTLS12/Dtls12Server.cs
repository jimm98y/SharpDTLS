// SharpDTLS
// Copyright (C) 2026 Lukas Volf
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE 
// SOFTWARE.

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using SharpDTLS.Protocol12.Messages;
using SharpDTLS.UDP;
using System;
using System.Linq;
using System.Net;

namespace SharpDTLS.Protocol12.DTLS12
{
    internal class Dtls12DataReceivedEventArgs : EventArgs
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
    internal class Dtls12Server : Dtls12ServerBase
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
