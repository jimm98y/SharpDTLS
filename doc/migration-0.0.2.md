# Migrating from SharpDTLS 0.0.2

Starting with the next release, SharpDTLS's public API uses only .NET types. Certificates are
`X509Certificate2`, distinguished names are `X500DistinguishedName`, and EC keys are `ECParameters`.
Everything else is `byte[]`. BouncyCastle still does the cryptography inside the library, but your
code no longer needs a reference to it.

Most applications only have to change how they pass their certificate and key, and the signature of
their certificate validators. The sections below cover each change.

## At a glance

| 0.0.2 | Now |
|---|---|
| `new DtlsServer(transport, keyPair, certificate)` | `new DtlsServer(transport, new ServerCredentials(certificate))` |
| `new TlsServer(keyPair, certificate)` | `new TlsServer(new ServerCredentials(certificate))` |
| `new ServerCredentials(keyPair, certificate, intermediates)` | `new ServerCredentials(certificate, intermediates)` |
| `new CertificateCredentials(keyPair, certificate, intermediates)` | `new CertificateCredentials(certificate, intermediates)` |
| `CertificateCredentials.KeyPair` | removed: the key is the certificate's own (`HasPrivateKey`), or the PKCS#8 bytes you passed |
| `client.ClientCertificate`, `ClientCertificateKeyPair`, `ClientIntermediateCertificates` | `client.ClientCredentials = new CertificateCredentials(certificate, intermediates)` |
| `Func<X509Certificate, IReadOnlyList<byte[]>, bool>` validators | `Func<X509Certificate2, IReadOnlyList<byte[]>, bool>` |
| `CertificateValidator(IEnumerable<X509Certificate>)` | `CertificateValidator(IEnumerable<X509Certificate2>)` |
| `CertificateValidator.HostNameValidator`: `Func<X509Certificate, string, bool>` | `Func<X509Certificate2, string, bool>` |
| `OcspStapleValidator(IEnumerable<X509Certificate>)` | `OcspStapleValidator(IEnumerable<X509Certificate2>)` |
| `TlsConnectionBase.PeerCertificate`, `LocalCertificate`: `X509Certificate` | `X509Certificate2` |
| `client.CertificateAuthorities`, `server.ClientCertificateAuthorities`, `server.IntermediateCertificates`: `IList<X509Certificate>` | `IList<X509Certificate2>` |
| `CertificateSelectionContext.CertificateAuthorities`: `IReadOnlyList<X509Name>` | `IReadOnlyList<X500DistinguishedName>` |
| `SrpVerifier(Srp6GroupParameters, byte[], BigInteger)` | `SrpVerifier(SrpGroup, byte[] salt, byte[] verifier)` |
| `SrpVerifier.Group`, `Verifier`, `StandardGroups` | `SrpGroup`, `byte[]`, `IReadOnlyList<SrpGroup>` |
| `PwdCredential.GenerateProtectionKeyPair()`: `AsymmetricCipherKeyPair` | `ECParameters` (with `D` and `Q`) |
| `server.PwdProtectionKey`: `ECPrivateKeyParameters` | `ECParameters?` with `D` |
| `client.PwdProtectionKey`: `ECPublicKeyParameters` | `ECParameters?` with `Q` only |
| (new) | `client.Crypto`, `server.Crypto`: `ITlsCrypto`, `BouncyCastleTlsCrypto` by default, or `NetTlsCrypto` |

Some things work as before:
- `new DtlsServer(transport)` and `new TlsServer()` without credentials still generate a self-signed certificate.
- `ICertificateValidator.Validate` still receives the chain as DER.
- `ForServer` and `ForClient` are used the same way.

## Certificates and keys

The key now comes with the certificate. Load the certificate the way you would for `SslStream`:

```cs
// .NET 5+: a PEM certificate and key
var certificate = X509Certificate2.CreateFromPemFile("server.crt", "server.key");

// any framework: a PFX / PKCS#12 file
var certificate = new X509Certificate2("server.pfx", password, X509KeyStorageFlags.Exportable);

var server = new DtlsServer(transport, new ServerCredentials(certificate, intermediates));
```

With the default `BouncyCastleTlsCrypto`, the private key must be **exportable**, because it is
handed to BouncyCastle:
- Load a PFX with `X509KeyStorageFlags.Exportable`. Keys from `CreateFromPemFile` and from
  `CertificateRequest.CreateSelfSigned` can be exported as they are.
- For keys that can't be exported, such as keys in the Windows certificate store, smart cards or
  HSMs, use `NetTlsCrypto` (see [The crypto provider](#the-crypto-provider)).
- A key that can't be exported fails the handshake, not the constructor: the key is exported the
  first time it is needed.

**Ed25519, Ed448 and static-DH keys.** .NET has no usable type for these keys on every framework. Pass the key as PKCS#8 DER
next to the certificate:

```cs
var credentials = new ServerCredentials(certificate, pkcs8PrivateKey, intermediates);
```

**Raw public keys (RFC 7250).** A server or client that authenticates only with a raw public key
can pass the PKCS#8 key and no certificate. This works for RSA, EC, Ed25519 and Ed448 keys:

```cs
new ServerCredentials(null, pkcs8PrivateKey)
```

A PSK-only server passes `null` credentials.

**Lists are copied when set.** `server.IntermediateCertificates`, `server.ClientCertificateAuthorities`
and `client.CertificateAuthorities` are converted when you assign them. To change them, assign a new
list; adding to the old one has no effect.

### Keeping BouncyCastle objects you already have

If your code already creates BouncyCastle certificates and key pairs, convert them where you
construct the credentials:

```cs
using Org.BouncyCastle.Pkcs;

var certificate = new X509Certificate2(bcCertificate.GetEncoded());
byte[] pkcs8 = PrivateKeyInfoFactory.CreatePrivateKeyInfo(bcKeyPair.Private).GetEncoded();
var credentials = new ServerCredentials(certificate, pkcs8);
```

Intermediates: `new X509Certificate2(bcIntermediate.GetEncoded())` for each.
Trusted roots and OCSP issuers convert the same way.

## Client certificates

Replace the three client properties with one `CertificateCredentials`:

```cs
// 0.0.2
client.ClientCertificate = certificate;
client.ClientCertificateKeyPair = keyPair;
client.ClientIntermediateCertificates = intermediates;

// now
client.ClientCredentials = new CertificateCredentials(certificate, intermediates);
```

`ClientCredentialsSelector` is unchanged. It still returns `CertificateCredentials`, built as shown above.

## Validators

Validators now receive an `X509Certificate2`. The chain is still DER, end entity first. A lambda
that ignores the certificate needs no change:

```cs
client.ServerCertificateValidator = (certificate, chain) => true;
```

A validator that pins a fingerprint can use .NET directly (.NET 5+):

```cs
client.ServerCertificateValidator = (certificate, chain) =>
    certificate.GetCertHashString(HashAlgorithmName.SHA256) == expectedFingerprint;
```

Before, this needed BouncyCastle's `GetEncoded()` and your own hashing.

`PeerCertificate` and `LocalCertificate` return an `X509Certificate2`:
- The connection owns it, so don't dispose it.
- Use `.RawData` where you used `.GetEncoded()`.

## SRP

`SrpVerifier.Create(identity, password)` without a group still works. If you pass a group, take it
from `SrpVerifier.StandardGroups`, which now holds `SrpGroup` objects. Build a custom group with
`new SrpGroup(n, g)`; both are big-endian unsigned bytes.

A verifier you stored as a `BigInteger` becomes `verifier.ToByteArrayUnsigned()`.

## TLS-PWD

`PwdCredential.GenerateProtectionKeyPair()` returns `ECParameters`:

```cs
ECParameters key = PwdCredential.GenerateProtectionKeyPair();
server.PwdProtectionKey = key;                                     // D and Q
client.PwdProtectionKey = new ECParameters { Curve = key.Curve, Q = key.Q }; // public part only
```

The key must be on a named curve. `null` turns protection off, as before.

## The crypto provider

The private-key operations (signing, RSA key transport and static key agreement) go through the
`ITlsCrypto` interface. You can set it on clients and servers:

```cs
server.Crypto = new NetTlsCrypto();
```

- **`BouncyCastleTlsCrypto`** (the default) exports the key and uses BouncyCastle. Every key type and
  protocol version works.
- **`NetTlsCrypto`** signs and decrypts RSA and ECDSA keys with the certificate's own `RSA` / `ECDsa`,
  so keys that can't be exported work too.
  - It falls back to BouncyCastle for PKCS#8 keys, Ed25519, Ed448, DSA, DH and static ECDH.
  - It also falls back for the MD5+SHA-1 RSA signature of TLS 1.0/1.1 and DTLS 1.0, which needs an
    exportable key.
  - It doesn't own the keys and isn't disposable.
  - RSA key transport (the `TLS_RSA_*` suites) uses the platform's PKCS#1 v1.5 decryption, which
    may take longer on bad padding than on good padding. BouncyCastle's decryption doesn't have this
    problem. These suites are off by default; leave them off.

To sign some other way, implement `ITlsCrypto`, for example to keep keys in a remote signing
service. A good base class is `BouncyCastleTlsCrypto`: override what you handle and leave the rest
to it.

## BouncyCastle as a dependency

SharpDTLS still depends on the `BouncyCastle.Cryptography` package. If your code referenced
BouncyCastle only to call SharpDTLS, you can drop its `using` directives.
