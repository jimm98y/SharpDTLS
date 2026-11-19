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

using SharpDTLS.Protocol13;
using System;

namespace SharpDTLS
{
#if NETCOREAPP
    /// <summary>.NET's ECDH on the NIST curves, and ML-KEM where the platform has it (.NET 10).</summary>
    internal static class NetKeyShares
    {
        /// <summary>Null for a group .NET has no key for here.</summary>
        public static ITlsKeyShare Create(ushort group)
        {
            System.Security.Cryptography.ECCurve? curve = group switch
            {
                Dtls13Groups.Secp256r1 => System.Security.Cryptography.ECCurve.NamedCurves.nistP256,
                Dtls13Groups.Secp384r1 => System.Security.Cryptography.ECCurve.NamedCurves.nistP384,
                Dtls13Groups.Secp521r1 => System.Security.Cryptography.ECCurve.NamedCurves.nistP521,
                _ => null,
            };
            if (curve == null)
                return null;
            var ecdh = System.Security.Cryptography.ECDiffieHellman.Create(curve.Value);
            var parameters = ecdh.ExportParameters(includePrivateParameters: TlsInspector.Current != null);
            int fieldLength = parameters.Q.X.Length;
            byte[] share = new byte[1 + 2 * fieldLength];
            share[0] = 0x04;
            parameters.Q.X.CopyTo(share, 1);
            parameters.Q.Y.CopyTo(share, 1 + fieldLength);
            if (TlsInspector.Current is { } inspector)
                TlsInspector.KeyExchange(inspector, group, parameters.D, share);
            return new KeyShare(share, peer =>
            {
                using (ecdh)
                {
                    BcKeyShares.Expect(peer, share.Length);
                    if (peer[0] != 0x04)
                        throw new DtlsException(AlertDescription.IllegalParameter, "Invalid elliptic curve key share.");
                    var peerParameters = new System.Security.Cryptography.ECParameters
                    {
                        Curve = curve.Value,
                        Q = new System.Security.Cryptography.ECPoint { X = peer.AsSpan(1, fieldLength).ToArray(), Y = peer.AsSpan(1 + fieldLength).ToArray() },
                    };
                    try
                    {
                        // the import refuses a point off the curve
                        using var peerKey = System.Security.Cryptography.ECDiffieHellman.Create(peerParameters);
                        return ecdh.DeriveRawSecretAgreement(peerKey.PublicKey);
                    }
                    catch (System.Security.Cryptography.CryptographicException ex)
                    {
                        throw new DtlsException(AlertDescription.IllegalParameter, "Invalid elliptic curve key share.", ex);
                    }
                }
            });
        }
    }
#endif
}
