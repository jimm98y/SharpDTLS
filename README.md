# SharpDTLS
DTLS 1.0/1.2/1.3 and TLS 1.0/1.1/1.2/1.3 client and server written in C#. The cryptography comes from [BouncyCastle](https://github.com/bcgit/bc-csharp); the protocols are implemented here. Targets `netstandard2.0`, `net8.0` and `net10.0`, so it runs on .NET Framework, .NET and anywhere else .NET Standard does.

[![NuGet version](https://img.shields.io/nuget/v/SharpDTLS.svg?style=flat-square)](https://www.nuget.org/packages/SharpDTLS)

A client offers every enabled version in one ClientHello and a server answers with the highest one both sides support. DTLS 1.2 and DTLS 1.3 are on by default, and so are TLS 1.2 and TLS 1.3. To enable the older versions, set `MinimumVersion`.

Implements the following RFCs:
1. The Transport Layer Security (TLS) Protocol Version 1.3 [RFC8446](https://www.rfc-editor.org/rfc/rfc8446)
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
To use your own certificate, pass it with its key pair: `new DtlsServer(serverTransport, keyPair, certificate)`.

Create the client and start the handshake. The handshake runs in the background and `HandshakeFinished` is raised when it completes, or `Failed` when it does not:
```cs
var clientTransport = new ClientTransport(new IPEndPoint(IPAddress.Loopback, 8888));
var client = new DtlsClient(clientTransport);
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
    client.ServerName = "example.com";
    client.ServerCertificateValidator = new CertificateValidator().ForServer("example.com");
});
await tls.WriteAsync(request, 0, request.Length);
int read = await tls.ReadAsync(buffer, 0, buffer.Length);
```
On the server side, `TlsStream.AcceptAsync(new TlsServer(), stream)` serves a client connected on the stream.

## Certificate validation
By default, a client accepts any certificate from the server and only checks that the server holds its private key. To validate the chain against the operating system's trust store and check the host name, set `ServerCertificateValidator`:
```cs
client.ServerCertificateValidator = new CertificateValidator().ForServer("example.com");
```
To trust only your own CA, pass its certificate: `new CertificateValidator(new[] { caCertificate })`. A server checks client certificates the same way with `ForClient()`.

## Public API
The public API is listed and checked on every build. See [doc/public-api.md](doc/public-api.md) for how to add to it or change it.
