# SharpDTLS
DTLS 1.0/1.2/1.3 and TLS 1.0/1.1/1.2/1.3 client and server written in C#. The cryptography comes from [BouncyCastle](https://github.com/bcgit/bc-csharp); the protocols are implemented here. Targets `netstandard2.0`, `net472`, `net8.0` and `net10.0`.

[![NuGet version](https://img.shields.io/nuget/v/SharpDTLS.svg?style=flat-square)](https://www.nuget.org/packages/SharpDTLS)

A client offers every enabled version in one ClientHello and a server answers with the highest one both sides support. DTLS 1.2 and DTLS 1.3 are on by default, and so are TLS 1.2 and TLS 1.3. To enable the older versions, set `MinimumVersion`.

Implements the following RFCs:
1. The Transport Layer Security (TLS) Protocol Version 1.3 [RFC9846](https://www.rfc-editor.org/rfc/rfc9846) (obsoletes RFC8446)
1. The Datagram Transport Layer Security (DTLS) Protocol Version 1.3 [RFC9147](https://www.rfc-editor.org/rfc/rfc9147)
1. The Transport Layer Security (TLS) Protocol Version 1.2 [RFC5246](https://www.rfc-editor.org/rfc/rfc5246)
1. Datagram Transport Layer Security Version 1.2 [RFC6347](https://www.rfc-editor.org/rfc/rfc6347)
1. Connection Identifier for DTLS 1.2 [RFC9146](https://www.rfc-editor.org/rfc/rfc9146)
1. DTLS Extension to Establish Keys for the Secure Real-time Transport Protocol (SRTP) [RFC5764](https://www.rfc-editor.org/rfc/rfc5764)
1. TLS Extensions: server name, OCSP stapling and more [RFC6066](https://www.rfc-editor.org/rfc/rfc6066)
1. Application-Layer Protocol Negotiation [RFC7301](https://www.rfc-editor.org/rfc/rfc7301)
1. Raw Public Keys in TLS and DTLS [RFC7250](https://www.rfc-editor.org/rfc/rfc7250)
1. TLS Certificate Compression [RFC8879](https://www.rfc-editor.org/rfc/rfc8879)
1. Record Size Limit Extension for TLS [RFC8449](https://www.rfc-editor.org/rfc/rfc8449)
1. Keying Material Exporters for TLS [RFC5705](https://www.rfc-editor.org/rfc/rfc5705)
1. Session resumption with session tickets [RFC5077](https://www.rfc-editor.org/rfc/rfc5077), extended master secret [RFC7627](https://www.rfc-editor.org/rfc/rfc7627)
1. Pre-shared keys [RFC4279](https://www.rfc-editor.org/rfc/rfc4279), SRP [RFC5054](https://www.rfc-editor.org/rfc/rfc5054) and TLS-PWD [RFC8492](https://www.rfc-editor.org/rfc/rfc8492)

## DTLS
The DTLS server and client send and receive datagrams through a transport: `ServerTransport` and `ClientTransport` in `SharpDTLS.UDP` use a UDP socket. To run DTLS over something else, such as an ICE connection, implement `IServerTransport` or `IClientTransport`.

Create the server. Without a key pair and a certificate it generates a self-signed certificate:
```cs
var serverTransport = new ServerTransport(new IPEndPoint(IPAddress.Any, 8888));
var server = new DtlsServer(serverTransport);
server.ApplicationDataReceived += (sender, e) =>
{
    Console.WriteLine($"Server received: {Encoding.UTF8.GetString(e.Data)}");
    e.Connection.SendApplicationData(Encoding.UTF8.GetBytes("Hello from server!"));
};
```
To use your own certificate, pass it with its key pair: `new DtlsServer(serverTransport, keyPair, certificate)`. A server keeps at most `MaxConnections` connections (10,000 by default) and creates one only for a client that passed the cookie exchange.

Create the client and start the handshake. The handshake runs in the background and `HandshakeFinished` is raised when it completes, or `Failed` when it does not:
```cs
var clientTransport = new ClientTransport(new IPEndPoint(IPAddress.Loopback, 8888));
var client = new DtlsClient(clientTransport);
// the server's certificate is self-signed: accept it here (pin its fingerprint in real use, see Certificate validation)
client.ServerCertificateValidator = (certificate, chain) => true;
client.HandshakeFinished += (sender, e) =>
{
    Console.WriteLine($"Handshake finished: version 0x{client.NegotiatedVersion:X4}");
    client.SendApplicationData(Encoding.UTF8.GetBytes("Hello from client!"));
};
client.ApplicationDataReceived += (sender, data) => Console.WriteLine($"Client received: {Encoding.UTF8.GetString(data)}");
client.Failed += (sender, ex) => Console.WriteLine($"Handshake failed: {ex.Message}");
client.BeginHandshake();
```
When done, call `client.Close()` and dispose of the transports.

## TLS
`TlsStream` runs TLS over any `Stream`, such as a `NetworkStream`, and is a `Stream` itself:
```cs
using var tcp = new TcpClient();
await tcp.ConnectAsync("example.com", 443);
using var tls = await TlsStream.ConnectAsync(tcp.GetStream(), client =>
{
    client.ServerName = "example.com"; // the chain is validated, and must match this name
});
await tls.WriteAsync(request, 0, request.Length);
int read = await tls.ReadAsync(buffer, 0, buffer.Length);
```
On the server side, `TlsStream.AcceptAsync(new TlsServer(), stream)` serves a client connected on the stream. A `TlsServer` listening with `Start` closes a client that has not completed its handshake within `HandshakeTimeout` (30 s), and accepts at most `MaxPendingHandshakes` (1,000) at once.

## Certificate validation
By default, a client validates the server's chain against the operating system's trust store and checks it against `ServerName`; a server that asks for a client certificate validates its chain the same way. A raw public key is refused unless `ServerRawPublicKeyValidator` (or `ClientRawPublicKeyValidator`) accepts it.

To validate otherwise, set `ServerCertificateValidator`. To trust only your own CA, pass its certificate:
```cs
client.ServerCertificateValidator = new CertificateValidator(new[] { caCertificate }).ForServer("example.com");
```
A server checks client certificates the same way with `ClientCertificateValidator` and `ForClient()`. For a self-signed certificate whose fingerprint is known, as in WebRTC, compare the fingerprint in the validator; `(certificate, chain) => true` accepts any certificate, checking only that the peer holds its private key.

`CertificateValidator` is the default implementation of `ICertificateValidator`. To validate some other way, implement `Validate`, which throws a `DtlsException` with the alert to send when the chain is not acceptable, and plug it in the same way:
```cs
client.ServerCertificateValidator = new MyCertificateValidator().ForServer("example.com");
```
