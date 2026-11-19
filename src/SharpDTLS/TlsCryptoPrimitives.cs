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
    /// <summary>The AEAD ciphers of record protection; the key length picks the variant (AES-128 or AES-256).</summary>
    public enum TlsAeadAlgorithm
    {
        AesGcm,
        AesCcm,
        /// <summary>AES-CCM with an 8-byte tag (RFC 6655).</summary>
        AesCcm8,
        ChaCha20Poly1305,
        CamelliaGcm,
        AriaGcm,
    }

    /// <summary>The block ciphers of CBC record protection, and of the DTLS 1.3 record number mask (AES).</summary>
    public enum TlsBlockCipherAlgorithm
    {
        Aes,
        Camellia,
        Aria,
        Seed,
        TripleDes,
        Des,
        Idea,
    }

    public enum TlsHashAlgorithm
    {
        Md5,
        Sha1,
        Sha256,
        Sha384,
        Sha512,
    }

    /// <summary>
    /// An AEAD cipher of one key, used for every record of that key. Not thread-safe. The output may be the input itself
    /// (the same start), so a record can be protected in place.
    /// </summary>
    public interface ITlsAead
    {
        int TagLength { get; }

        /// <summary>Writes the ciphertext and then the tag: <paramref name="plaintext"/>.Length + <see cref="TagLength"/> bytes.</summary>
        void Seal(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> plaintext, Span<byte> ciphertextAndTag);

        /// <summary>
        /// Writes <paramref name="ciphertextAndTag"/>.Length - <see cref="TagLength"/> bytes of plaintext; false when the tag
        /// does not authenticate, the plaintext then being of no use.
        /// </summary>
        bool Open(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> ciphertextAndTag, Span<byte> plaintext);
    }

    /// <summary>A block cipher of one key in CBC mode, without padding. Not thread-safe; the output may be the input itself.</summary>
    public interface ITlsBlockCipher
    {
        int BlockSize { get; }

        /// <summary><paramref name="input"/> is whole blocks; one block of a zero IV is the block cipher itself (ECB).</summary>
        void EncryptCbc(ReadOnlySpan<byte> iv, ReadOnlySpan<byte> input, Span<byte> output);

        void DecryptCbc(ReadOnlySpan<byte> iv, ReadOnlySpan<byte> input, Span<byte> output);
    }

    /// <summary>A hash or an HMAC of one key, reused: <see cref="Finish"/> starts it over. Not thread-safe.</summary>
    public interface ITlsHash
    {
        int HashLength { get; }

        void Append(ReadOnlySpan<byte> data);

        /// <summary>Writes <see cref="HashLength"/> bytes and starts over.</summary>
        void Finish(Span<byte> destination);
    }
}
