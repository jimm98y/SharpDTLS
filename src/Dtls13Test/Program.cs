

using SharpDTLS;
using SharpDTLS.DTLS10;
using SharpDTLS.DTLS12;
using SharpDTLS.DTLS13;
using SharpSRTP.UDP;
using System;
using System.Text;

var serverTransport = new ServerTransport();
var clientTransport = new ClientTransport();

var server = new Dtls13Server(serverTransport);
var client = new Dtls13Client(clientTransport);
//var server = new Dtls12Server(serverTransport);
//var client = new Dtls12Client(clientTransport);
//var server = new Dtls10Server(serverTransport);
//var client = new Dtls10Client(clientTransport);

client.HandshakeFinished += (sender, args) =>
{
    client.SendApplicationData(Encoding.UTF8.GetBytes("Hello from client!"));
};
client.BeginHandshake();

Console.ReadLine();