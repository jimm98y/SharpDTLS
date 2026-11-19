using System.Text;
using SharpDTLS;
using SharpDTLS.UDP;

// listens on UDP 0.0.0.0:8888 with a self-signed certificate
var server = new DtlsServer(new ServerTransport());
server.ApplicationDataReceived += (connection, data) =>
{
    Console.WriteLine($"Received: {Encoding.UTF8.GetString(data)}");
    connection.SendApplicationData(data); // echo it back
};
Console.WriteLine("DTLS server listening on UDP port 8888, press Enter to stop.");
Console.ReadLine();
