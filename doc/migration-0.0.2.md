# Migrating from SharpDTLS 0.0.2

Starting with SharpDTLS 0.1.0, the public API uses only .NET types. Certificates are
`X509Certificate2`, distinguished names are `X500DistinguishedName`, and EC keys are `ECParameters`.
Everything else is `byte[]`. BouncyCastle still does the cryptography inside the library, but your
code no longer needs a reference to it.

Received application data and datagrams are now handed over as `ReadOnlySpan<byte>`, so that an
established connection allocates nothing per record.

Most applications only have to change how they pass their certificate and key, their certificate
validators and their data handlers. The sections below cover each change.

Code that compiles unchanged still has to be rebuilt: `SendApplicationData` and the transports' `Send`
take spans now, so assemblies built against 0.0.2 don't bind to 0.1.0.

## At a glance

| 0.0.2 | Now |
|---|---|
| `new DtlsServer(transport, keyPair, certificate)` | `new DtlsServer(transport, new TransportCertificate(certificate))` |
| `new TlsServer(keyPair, certificate)` | `new TlsServer(new TransportCertificate(certificate))` |
| `ServerCredentials`, `CertificateCredentials` | `TransportCertificate`, one type for servers and clients; `OcspResponse` is on it |
| `new ServerCredentials(keyPair, certificate, intermediates)` | `new TransportCertificate(certificate, intermediates)` |
| `new CertificateCredentials(keyPair, certificate, intermediates)` | `new TransportCertificate(certificate, intermediates)` |
| `CertificateCredentials.Certificate`, `IntermediateCertificates`: `X509Certificate`, `IList<X509Certificate>` | `X509Certificate2`, `IList<X509Certificate2>` |
| `CertificateCredentials.KeyPair` | removed: the key is the certificate's own (`HasPrivateKey`), or the PKCS#8 bytes you passed |
| `client.ClientCertificate`, `ClientCertificateKeyPair`, `ClientIntermediateCertificates` | `client.ClientCredentials = new TransportCertificate(certificate, intermediates)` |
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
| `ApplicationDataReceived`: `EventHandler<byte[]>` (clients, connections) | `TlsDataHandler`: `(connection, ReadOnlySpan<byte> data)` |
| `DtlsServer.ApplicationDataReceived`, `EarlyDataReceived`: `EventHandler<DtlsDataReceivedEventArgs>` | `TlsDataHandler`; `e.RemoteEndPoint` is `connection.RemoteEndPoint` |
| `TlsServer.ApplicationDataReceived`, `EarlyDataReceived`: `EventHandler<TlsDataReceivedEventArgs>` | `TlsDataHandler` |
| `SendApplicationData(byte[])`, `DtlsServer.SendApplicationData(EndPoint, byte[])` | `ReadOnlySpan<byte>`: a `byte[]` still converts |
| `IServerTransport`, `IClientTransport`: `event EventHandler<byte[]> OnDataReceived`, `Send(byte[])` | `event DatagramHandler OnDataReceived`, `Send(ReadOnlySpan<byte>)` |

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

var server = new DtlsServer(transport, new TransportCertificate(certificate, intermediates));
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
var credentials = new TransportCertificate(certificate, pkcs8PrivateKey, intermediates);
```

**Raw public keys (RFC 7250).** A server or client that authenticates only with a raw public key
can pass the PKCS#8 key and no certificate. This works for RSA, EC, Ed25519 and Ed448 keys:

```cs
new TransportCertificate(null, pkcs8PrivateKey)
```

A PSK-only server passes `null` credentials.

**Self-signed certificates.** For tests, demos and peers that pin the certificate, the library makes
one for you, as a server's credentials or a client's:

```cs
var rsa = CertificateBuilder.CreateSelfSigned("example.test");                            // RSA-2048
var ec = CertificateBuilder.CreateSelfSigned("example.test", ECCurve.NamedCurves.nistP384); // any named curve
```

It works on every framework, and `NetTlsCrypto` signs with it too (through BouncyCastle).

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
var credentials = new TransportCertificate(certificate, pkcs8);
```

Intermediates: `new X509Certificate2(bcIntermediate.GetEncoded())` for each.
Trusted roots and OCSP issuers convert the same way.

## Client certificates

Replace the three client properties with one `TransportCertificate`:

```cs
// 0.0.2
client.ClientCertificate = certificate;
client.ClientCertificateKeyPair = keyPair;
client.ClientIntermediateCertificates = intermediates;

// now
client.ClientCredentials = new TransportCertificate(certificate, intermediates);
```

`ClientCredentialsSelector` is used as before. It returns a `TransportCertificate`, built as shown above, as the servers' `CredentialsSelector` and `CertificateSelector` do.

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

The key must be on a named curve. `null` turns protection off, as before. A client refuses a key
that has `D` with an `ArgumentException`: the server's private key must not be handed to clients.

## Received data

Data events hand over a span that is valid only during the call: the library reuses its buffer for
the next record. Copy what you keep:

```cs
// 0.0.2
server.ApplicationDataReceived += (sender, e) => queue.Enqueue(e.Data);
client.ApplicationDataReceived += (sender, data) => queue.Enqueue(data);

// now
server.ApplicationDataReceived += (connection, data) => queue.Enqueue(data.ToArray());
client.ApplicationDataReceived += (connection, data) => queue.Enqueue(data.ToArray());
```

- The first argument is the connection that received the data, not the client or server object. On a
  server it is a `Tls12ServerConnection` or `Tls13ServerConnection`; its `RemoteEndPoint` replaces
  `e.RemoteEndPoint`, and replying is `connection.SendApplicationData(...)`.
- A handler that only reads the data, for example `Encoding.UTF8.GetString(data)` on .NET Core 2.1 and
  later, needs no copy.
- `SendApplicationData` copies the data before it returns, so the caller may reuse its buffer.

## Transports

A custom transport implements the span interfaces:

```cs
sealed class MyTransport : IServerTransport
{
    public event DatagramHandler OnDataReceived;

    public void Send(EndPoint endpoint, ReadOnlySpan<byte> datagram) => /* send it; don't keep the span */;

    // on each datagram received, from a buffer you may reuse once the call returns
    void Received(EndPoint from, byte[] buffer, int length) => OnDataReceived?.Invoke(from, buffer.AsSpan(0, length));
}
```

`IClientTransport` is the same without the endpoint on `Send`. The `ServerTransport` and
`ClientTransport` classes receive into one buffer and send from spans; on .NET 8 and later the server
also keeps one `IPEndPoint` per source address instead of creating one for every datagram. Those
instances are shared by every datagram and connection of that address: read them, don't change them.

## The crypto provider

The private-key operations (signing, RSA key transport and static key agreement) go through the
`ITlsCrypto` interface. You can set it on clients and servers:

```cs
server.Crypto = new NetTlsCrypto();
```

- **`BouncyCastleTlsCrypto`** (the default) exports the key and uses BouncyCastle. Every key type and
  protocol version works.
- **`NetTlsCrypto`** signs and decrypts RSA and ECDSA keys with the certificate's own `RSA` / `ECDsa`,
  and on .NET 8 and later DSA keys and static ECDH with its own `DSA` / `ECDiffieHellman`, so keys that
  can't be exported work too: a certificate of the Windows store, a TPM or a smart card, over DTLS and TLS,
  as the server's or the client's.
  - It falls back to BouncyCastle for PKCS#8 keys, Ed25519, Ed448, DH, and DSA and static ECDH before
    .NET 8.
  - It also falls back for the MD5+SHA-1 RSA signature of TLS 1.0/1.1 and DTLS 1.0, which needs an
    exportable key.
  - It doesn't own the keys and isn't disposable.
  - RSA key transport (the `TLS_RSA_*` suites) uses the platform's PKCS#1 v1.5 decryption, which
    may take longer on bad padding than on good padding. BouncyCastle's decryption doesn't have this
    problem. These suites are off by default; leave them off.

`ITlsCrypto` also creates the record protection: `CreateAead`, `CreateBlockCipher`, `CreateHash`
and `CreateHmac` are called once per key, and the object is used for every record of that key.
- With **`NetTlsCrypto`** on .NET 8 and later, records are protected by .NET's `AesGcm`, `AesCcm` and
  `ChaCha20Poly1305` (where the platform supports it), and no record allocates anything.
- With **`BouncyCastleTlsCrypto`**, BouncyCastle's GCM, CCM and ChaCha20-Poly1305 still allocate as they
  are set up for each record's nonce: with BouncyCastle 2.7 about 1.1 KB on each side of a record for
  AES-GCM (sealing it, then opening it) and 540 bytes for ChaCha20-Poly1305. CBC suites, the record number mask and the HMACs allocate nothing. On .NET
  Framework and .NET Standard both providers use BouncyCastle.
- Over TCP, `TlsStream`'s `Task` methods allocate their tasks as any `Stream`'s do.

The rest of the cryptography goes through it too:
- the handshake's hashes, the TLS PRF and the TLS 1.3 key schedule (`CreateHash`, `CreateHmac`);
- the key exchange (`CreateKeyShare` for (EC)DHE, X25519, X448, FFDHE and ML-KEM, `Encapsulate` for ML-KEM);
- the peer's signatures (`Verify`, with the peer's key as DER SubjectPublicKeyInfo) and RSA key transport
  (`EncryptPreMasterSecret`).

`NetTlsCrypto` uses .NET's ECDH for P-256, P-384 and P-521 and .NET's RSA and ECDSA to verify signatures
on .NET 8 and later. X25519, X448, FFDHE, ML-KEM, Ed25519, Ed448 and DSA stay on BouncyCastle.

To sign some other way, implement `ITlsCrypto`, for example to keep keys in a remote signing
service. A good base class is `BouncyCastleTlsCrypto`: override what you handle and leave the rest
to it.

## BouncyCastle as a dependency

SharpDTLS still depends on the `BouncyCastle.Cryptography` package. If your code referenced
BouncyCastle only to call SharpDTLS, you can drop its `using` directives.
