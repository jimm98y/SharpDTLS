using SharpDTLS;
using SharpDTLS.UDP;
using System;
using System.Text;

var serverTransport = new ServerTransport();
var clientTransport = new ClientTransport();

// Both negotiate DTLS 1.3; set MaximumVersion = DtlsVersion.Dtls12 on either side for DTLS 1.2.
var server = new DtlsServer(serverTransport);
var client = new DtlsClient(clientTransport);

server.ApplicationDataReceived += (sender, e) =>
{
    Console.WriteLine($"Server received: {Encoding.UTF8.GetString(e.Data)}");
};
client.HandshakeFinished += (sender, args) =>
{
    Console.WriteLine($"Handshake finished: version 0x{client.NegotiatedVersion:X4}");
    client.SendApplicationData(Encoding.UTF8.GetBytes("Hello from client!"));
};
client.BeginHandshake();

Console.ReadLine();
