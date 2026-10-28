namespace SharpDTLS
{
    /// <summary>
    /// Signature schemes (RFC 8446 §4.2.3; TLS 1.2 hash/signature pairs, RFC 5246 §7.4.1.4.1, share the code points).
    /// In TLS/DTLS 1.2 the ECDSA schemes are not bound to a curve.
    /// </summary>
    public static class SignatureSchemes
    {
        public const ushort RsaPkcs1Sha1 = 0x0201;
        public const ushort DsaSha1 = 0x0202;
        public const ushort EcdsaSha1 = 0x0203;
        public const ushort RsaPkcs1Sha256 = 0x0401;
        public const ushort DsaSha256 = 0x0402;
        public const ushort EcdsaSecp256r1Sha256 = 0x0403;
        public const ushort RsaPkcs1Sha384 = 0x0501;
        public const ushort DsaSha384 = 0x0502;
        public const ushort EcdsaSecp384r1Sha384 = 0x0503;
        public const ushort RsaPkcs1Sha512 = 0x0601;
        public const ushort DsaSha512 = 0x0602;
        public const ushort EcdsaSecp521r1Sha512 = 0x0603;
        public const ushort RsaPssRsaeSha256 = 0x0804;
        public const ushort RsaPssRsaeSha384 = 0x0805;
        public const ushort RsaPssRsaeSha512 = 0x0806;
        public const ushort Ed25519 = 0x0807;
        public const ushort Ed448 = 0x0808;
    }
}
