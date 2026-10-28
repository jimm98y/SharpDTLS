

using SharpDTLS.Protocol10.DTLS10;
using SharpDTLS.Protocol12.DTLS12;
using SharpDTLS.Protocol13;
using SharpDTLS.Protocol13.DTLS13;
using SharpDTLS.UDP;
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