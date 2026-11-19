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
using System.Security.Cryptography;

namespace SharpDTLS
{
#if NETCOREAPP
    /// <summary>.NET's AES-GCM, AES-CCM and ChaCha20-Poly1305; disposed by the connection when it closes.</summary>
    internal sealed class NetAead : ITlsAead, IDisposable
    {
        private readonly AesGcm _gcm;
        private readonly AesCcm _ccm;
        private readonly System.Security.Cryptography.ChaCha20Poly1305 _chacha;

        private NetAead(AesGcm gcm, AesCcm ccm, System.Security.Cryptography.ChaCha20Poly1305 chacha, int tagLength)
        {
            _gcm = gcm;
            _ccm = ccm;
            _chacha = chacha;
            TagLength = tagLength;
        }

        /// <summary>Null when the platform lacks the algorithm.</summary>
        public static NetAead Create(TlsAeadAlgorithm algorithm, ReadOnlySpan<byte> key) => algorithm switch
        {
            TlsAeadAlgorithm.AesGcm when AesGcm.IsSupported => new NetAead(new AesGcm(key, 16), null, null, 16),
            TlsAeadAlgorithm.AesCcm when AesCcm.IsSupported => new NetAead(null, new AesCcm(key), null, 16),
            TlsAeadAlgorithm.AesCcm8 when AesCcm.IsSupported => new NetAead(null, new AesCcm(key), null, 8),
            TlsAeadAlgorithm.ChaCha20Poly1305 when System.Security.Cryptography.ChaCha20Poly1305.IsSupported
                => new NetAead(null, null, new System.Security.Cryptography.ChaCha20Poly1305(key), 16),
            _ => null,
        };

        public int TagLength { get; }

        public void Seal(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> plaintext, Span<byte> ciphertextAndTag)
        {
            var ciphertext = ciphertextAndTag.Slice(0, plaintext.Length);
            var tag = ciphertextAndTag.Slice(plaintext.Length, TagLength);
            if (_gcm != null)
                _gcm.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
            else if (_ccm != null)
                _ccm.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
            else
                _chacha.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
        }

        public bool Open(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> ciphertextAndTag, Span<byte> plaintext)
        {
            int length = ciphertextAndTag.Length - TagLength;
            if (length < 0)
                return false;
            var ciphertext = ciphertextAndTag.Slice(0, length);
            var tag = ciphertextAndTag.Slice(length);
            try
            {
                if (_gcm != null)
                    _gcm.Decrypt(nonce, ciphertext, tag, plaintext.Slice(0, length), associatedData);
                else if (_ccm != null)
                    _ccm.Decrypt(nonce, ciphertext, tag, plaintext.Slice(0, length), associatedData);
                else
                    _chacha.Decrypt(nonce, ciphertext, tag, plaintext.Slice(0, length), associatedData);
                return true;
            }
            catch (CryptographicException)
            {
                return false;
            }
        }

        public void Dispose()
        {
            _gcm?.Dispose();
            _ccm?.Dispose();
            _chacha?.Dispose();
        }
    }

    /// <summary>.NET's hashes and HMACs.</summary>
    internal sealed class NetHash : ITlsHash, IDisposable
    {
        private readonly IncrementalHash _hash;

        public NetHash(TlsHashAlgorithm hash, ReadOnlySpan<byte> key, bool hmac)
        {
            var name = hash switch
            {
                TlsHashAlgorithm.Md5 => HashAlgorithmName.MD5,
                TlsHashAlgorithm.Sha1 => HashAlgorithmName.SHA1,
                TlsHashAlgorithm.Sha256 => HashAlgorithmName.SHA256,
                TlsHashAlgorithm.Sha384 => HashAlgorithmName.SHA384,
                TlsHashAlgorithm.Sha512 => HashAlgorithmName.SHA512,
                _ => throw new ArgumentOutOfRangeException(nameof(hash)),
            };
            _hash = hmac ? IncrementalHash.CreateHMAC(name, key) : IncrementalHash.CreateHash(name);
        }

        public int HashLength => _hash.HashLengthInBytes;

        public void Append(ReadOnlySpan<byte> data) => _hash.AppendData(data);

        public void Finish(Span<byte> destination) => _hash.GetHashAndReset(destination);

        public void Dispose() => _hash.Dispose();
    }
#endif
}
