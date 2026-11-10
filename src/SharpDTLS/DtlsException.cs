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

using System;

namespace SharpDTLS
{
    /// <summary>
    /// TLS/DTLS alert descriptions (RFC 9846 §6, plus legacy values from RFC 5246).
    /// </summary>
    public enum AlertDescription : byte
    {
        CloseNotify                  = 0,
        UnexpectedMessage            = 10,
        BadRecordMac                 = 20,
        RecordOverflow               = 22,
        HandshakeFailure             = 40,
        BadCertificate               = 42,
        UnsupportedCertificate       = 43,
        CertificateRevoked           = 44,
        CertificateExpired           = 45,
        CertificateUnknown           = 46,
        IllegalParameter             = 47,
        UnknownCa                    = 48,
        AccessDenied                 = 49,
        DecodeError                  = 50,
        DecryptError                 = 51,
        ProtocolVersion              = 70,
        InsufficientSecurity         = 71,
        InternalError                = 80,
        InappropriateFallback        = 86,
        UserCanceled                 = 90,
        NoRenegotiation              = 100,
        MissingExtension             = 109,
        UnsupportedExtension         = 110,
        UnrecognizedName             = 112,
        BadCertificateStatusResponse = 113,
        UnknownPskIdentity           = 115,
        CertificateRequired          = 116,
        /// <summary>An error with no more specific alert (RFC 9846 §6.2).</summary>
        GeneralError                 = 117,
        NoApplicationProtocol        = 120,
    }

    /// <summary>
    /// A fatal protocol error. <see cref="Alert"/> is the alert that should be sent to the peer.
    /// </summary>
    public class DtlsException : Exception
    {
        public AlertDescription Alert { get; }

        public DtlsException(AlertDescription alert, string message) : base(message)
        {
            Alert = alert;
        }

        public DtlsException(AlertDescription alert, string message, Exception innerException) : base(message, innerException)
        {
            Alert = alert;
        }
    }

    /// <summary>
    /// A record that must be silently discarded (duplicate, unauthenticated or for an unknown epoch).
    /// Per RFC 9147 §4.5.2 such records do not terminate the connection.
    /// </summary>
    internal class DtlsRecordDiscardedException : Exception
    {
        public DtlsRecordDiscardedException(string message) : base(message) { }
        public DtlsRecordDiscardedException(string message, Exception innerException) : base(message, innerException) { }
    }

    /// <summary>A DTLS 1.3 record that failed authentication: discarded, but counted against the AEAD's integrity limit.</summary>
    internal sealed class DtlsRecordAuthenticationException : DtlsRecordDiscardedException
    {
        public DtlsRecordAuthenticationException(string message) : base(message) { }
    }
}
