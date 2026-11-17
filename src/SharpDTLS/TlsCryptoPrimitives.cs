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
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Security.Cryptography;

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

    /// <summary>BouncyCastle's primitives, built once per key; spans copied through buffers of their own where BouncyCastle has none.</summary>
    internal static class BcPrimitives
    {
        public static ITlsAead Aead(TlsAeadAlgorithm algorithm, ReadOnlySpan<byte> key) => algorithm switch
        {
            TlsAeadAlgorithm.AesGcm => new BcAead(() => new GcmBlockCipher(AesUtilities.CreateEngine()), key, 16),
            TlsAeadAlgorithm.AesCcm => new BcAead(() => new CcmBlockCipher(AesUtilities.CreateEngine()), key, 16),
            TlsAeadAlgorithm.AesCcm8 => new BcAead(() => new CcmBlockCipher(AesUtilities.CreateEngine()), key, 8),
            TlsAeadAlgorithm.ChaCha20Poly1305 => new BcAead(() => new Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305(), key, 16),
            TlsAeadAlgorithm.CamelliaGcm => new BcAead(() => new GcmBlockCipher(new CamelliaEngine()), key, 16),
            TlsAeadAlgorithm.AriaGcm => new BcAead(() => new GcmBlockCipher(new AriaEngine()), key, 16),
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm)),
        };

        public static ITlsBlockCipher BlockCipher(TlsBlockCipherAlgorithm algorithm, ReadOnlySpan<byte> key)
        {
            Func<IBlockCipher> create = algorithm switch
            {
                TlsBlockCipherAlgorithm.Aes => AesUtilities.CreateEngine,
                TlsBlockCipherAlgorithm.Camellia => () => new CamelliaEngine(),
                TlsBlockCipherAlgorithm.Aria => () => new AriaEngine(),
                TlsBlockCipherAlgorithm.Seed => () => new SeedEngine(),
                TlsBlockCipherAlgorithm.TripleDes => () => new DesEdeEngine(),
                TlsBlockCipherAlgorithm.Des => () => new DesEngine(),
                TlsBlockCipherAlgorithm.Idea => () => new IdeaEngine(),
                _ => throw new ArgumentOutOfRangeException(nameof(algorithm)),
            };
            return new BcBlockCipher(create, key);
        }

        public static IDigest Digest(TlsHashAlgorithm hash) => hash switch
        {
            TlsHashAlgorithm.Md5 => new MD5Digest(),
            TlsHashAlgorithm.Sha1 => new Sha1Digest(),
            TlsHashAlgorithm.Sha256 => new Sha256Digest(),
            TlsHashAlgorithm.Sha384 => new Sha384Digest(),
            TlsHashAlgorithm.Sha512 => new Sha512Digest(),
            _ => throw new ArgumentOutOfRangeException(nameof(hash)),
        };

#if !NETCOREAPP
        // BouncyCastle of .NET Framework and .NET Standard takes arrays alone: a buffer of the caller's, grown once.
        internal static byte[] Copy(ref byte[] buffer, ReadOnlySpan<byte> data)
        {
            if (buffer == null || buffer.Length < data.Length)
                buffer = new byte[Math.Max(data.Length, 64)];
            data.CopyTo(buffer);
            return buffer;
        }

        internal static byte[] Room(ref byte[] buffer, int length)
        {
            if (buffer == null || buffer.Length < length)
                buffer = new byte[Math.Max(length, 64)];
            return buffer;
        }
#endif
    }

    internal sealed class BcAead : ITlsAead
    {
        private readonly Func<IAeadCipher> _create;
        private readonly KeyParameter _key;
        // one cipher of each direction: each keeps its key schedule, and sealing never meets the nonce of an opening
        private Side _seal, _open;

        public BcAead(Func<IAeadCipher> create, ReadOnlySpan<byte> key, int tagLength)
        {
            _create = create;
            _key = new KeyParameter(key.ToArray());
            TagLength = tagLength;
        }

        public int TagLength { get; }

        public void Seal(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> plaintext, Span<byte> ciphertextAndTag)
            => (_seal ??= new Side(_create(), _key, TagLength, encrypt: true)).Process(nonce, associatedData, plaintext, ciphertextAndTag);

        public bool Open(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> ciphertextAndTag, Span<byte> plaintext)
        {
            if (ciphertextAndTag.Length < TagLength)
                return false;
            try
            {
                (_open ??= new Side(_create(), _key, TagLength, encrypt: false)).Process(nonce, associatedData, ciphertextAndTag, plaintext);
                return true;
            }
            catch (InvalidCipherTextException)
            {
                return false;
            }
        }

        private sealed class Side
        {
            private readonly IAeadCipher _cipher;
            private readonly KeyParameter _key;
            private readonly int _tagLength;
            private readonly bool _encrypt;
            private bool _keyed;

            // BouncyCastle keeps the nonce's array to refuse its reuse: two arrays of our own, in turn, so none is allocated.
            private readonly byte[][] _nonces = new byte[2][];
            private readonly AeadParameters[] _parameters = new AeadParameters[2];
            private int _turn;
#if !NETCOREAPP
            private byte[] _in, _out;
#endif

            public Side(IAeadCipher cipher, KeyParameter key, int tagLength, bool encrypt)
            {
                _cipher = cipher;
                _key = key;
                _tagLength = tagLength;
                _encrypt = encrypt;
            }

            public void Process(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> input, Span<byte> output)
            {
                int i = _turn ^= 1;
                if (_nonces[i] == null || _nonces[i].Length != nonce.Length)
                {
                    _nonces[i] = new byte[nonce.Length];
                    _parameters[i] = new AeadParameters(null, _tagLength * 8, _nonces[i]);
                }
                nonce.CopyTo(_nonces[i]);
                // the key once: of a null key, BouncyCastle keeps its key schedule (and GCM its tables)
                _cipher.Init(_encrypt, _keyed ? _parameters[i] : new AeadParameters(_key, _tagLength * 8, _nonces[i]));
                _keyed = true;
#if NETCOREAPP
                _cipher.ProcessAadBytes(associatedData);
                int written = _cipher.ProcessBytes(input, output);
                _cipher.DoFinal(output.Slice(written));
#else
                byte[] aad = BcPrimitives.Copy(ref _in, associatedData);
                _cipher.ProcessAadBytes(aad, 0, associatedData.Length);
                byte[] data = BcPrimitives.Copy(ref _in, input);
                byte[] result = BcPrimitives.Room(ref _out, _cipher.GetOutputSize(input.Length));
                int written = _cipher.ProcessBytes(data, 0, input.Length, result, 0);
                written += _cipher.DoFinal(result, written);
                result.AsSpan(0, written).CopyTo(output);
#endif
            }
        }
    }

    internal sealed class BcBlockCipher : ITlsBlockCipher
    {
        private readonly Func<IBlockCipher> _create;
        private readonly KeyParameter _key;
        private IBlockCipher _encrypt, _decrypt;
#if !NETCOREAPP
        private readonly byte[] _a, _b;
#endif

        public BcBlockCipher(Func<IBlockCipher> create, ReadOnlySpan<byte> key)
        {
            _create = create;
            _key = new KeyParameter(key.ToArray());
            BlockSize = create().GetBlockSize();
#if !NETCOREAPP
            _a = new byte[BlockSize];
            _b = new byte[BlockSize];
#endif
        }

        public int BlockSize { get; }

        public void EncryptCbc(ReadOnlySpan<byte> iv, ReadOnlySpan<byte> input, Span<byte> output)
        {
            var engine = _encrypt ??= Engine(true);
            Span<byte> block = stackalloc byte[BlockSize];
            ReadOnlySpan<byte> chain = iv;
            for (int i = 0; i < input.Length; i += BlockSize)
            {
                for (int j = 0; j < BlockSize; j++)
                    block[j] = (byte)(input[i + j] ^ chain[j]);
                Process(engine, block, output.Slice(i, BlockSize));
                chain = output.Slice(i, BlockSize);
            }
        }

        public void DecryptCbc(ReadOnlySpan<byte> iv, ReadOnlySpan<byte> input, Span<byte> output)
        {
            var engine = _decrypt ??= Engine(false);
            Span<byte> chain = stackalloc byte[BlockSize];
            Span<byte> next = stackalloc byte[BlockSize];
            Span<byte> block = stackalloc byte[BlockSize];
            iv.CopyTo(chain);
            for (int i = 0; i < input.Length; i += BlockSize)
            {
                input.Slice(i, BlockSize).CopyTo(next); // the ciphertext, before an in-place output overwrites it
                Process(engine, next, block);
                for (int j = 0; j < BlockSize; j++)
                    output[i + j] = (byte)(block[j] ^ chain[j]);
                next.CopyTo(chain);
            }
        }

        private IBlockCipher Engine(bool encrypt)
        {
            var engine = _create();
            engine.Init(encrypt, _key);
            return engine;
        }

        private void Process(IBlockCipher engine, ReadOnlySpan<byte> input, Span<byte> output)
        {
#if NETCOREAPP
            engine.ProcessBlock(input, output);
#else
            input.CopyTo(_a);
            engine.ProcessBlock(_a, 0, _b, 0);
            _b.AsSpan(0, BlockSize).CopyTo(output);
#endif
        }
    }

    internal sealed class BcHash : ITlsHash
    {
        private readonly IDigest _digest;
        private readonly IMac _mac;
#if !NETCOREAPP
        private byte[] _buffer;
#endif

        public BcHash(IDigest digest) => _digest = digest;

        public BcHash(IDigest digest, ReadOnlySpan<byte> key)
        {
            _mac = new HMac(digest);
            _mac.Init(new KeyParameter(key.ToArray()));
        }

        public int HashLength => _mac?.GetMacSize() ?? _digest.GetDigestSize();

        public void Append(ReadOnlySpan<byte> data)
        {
#if NETCOREAPP
            if (_mac != null)
                _mac.BlockUpdate(data);
            else
                _digest.BlockUpdate(data);
#else
            byte[] buffer = BcPrimitives.Copy(ref _buffer, data);
            if (_mac != null)
                _mac.BlockUpdate(buffer, 0, data.Length);
            else
                _digest.BlockUpdate(buffer, 0, data.Length);
#endif
        }

        public void Finish(Span<byte> destination)
        {
#if NETCOREAPP
            if (_mac != null)
                _mac.DoFinal(destination);
            else
                _digest.DoFinal(destination);
#else
            byte[] buffer = BcPrimitives.Room(ref _buffer, HashLength);
            if (_mac != null)
                _mac.DoFinal(buffer, 0);
            else
                _digest.DoFinal(buffer, 0);
            buffer.AsSpan(0, HashLength).CopyTo(destination);
#endif
        }
    }

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
