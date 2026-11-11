using System.Net.Sockets;
using System.Text;
using SharpDTLS;

using var tcp = new TcpClient();
await tcp.ConnectAsync("127.0.0.1", 4433);
// the sample server's certificate is self-signed: accept any (without a validator the chain is validated)
using var tls = await TlsStream.ConnectAsync(tcp.GetStream(), client => client.ServerCertificateValidator = (certificate, chain) => true);
await tls.WriteAsync(Encoding.UTF8.GetBytes("Hello over TLS!"));
var buffer = new byte[4096];
int read = await tls.ReadAsync(buffer);
Console.WriteLine($"Received: {Encoding.UTF8.GetString(buffer, 0, read)}");
