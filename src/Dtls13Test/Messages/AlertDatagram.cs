namespace Dtls13Test.Messages
{
    public class AlertDatagram : IDatagram
    {
        public ushort Alert { get; set; } = 0x0100; // close_notify
        public byte[] Bytes { get; private set; }

        public AlertDatagram()
        {  }

        public AlertDatagram(ushort alert)
        {
            this.Alert = alert;
        }

        public void FromBytes(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes)); if (bytes.Length < 3) throw new ArgumentException("Buffer too small for ServerAckDatagram.");

            this.Bytes = bytes.ToArray();
            this.Alert = (ushort)((bytes[0] << 8) | bytes[1]);

            if (bytes[2] != 0x15) throw new InvalidDataException("Unexpected record type (expected 0x15).");
        }


        public byte[] ToBytes()
        {
            byte[] data = new byte[3];

            data[0] = (byte)((this.Alert >> 8) & 0xFF);
            data[1] = (byte)(this.Alert & 0xFF);                      
            data[2] = 0x15; // Alert

            this.Bytes = data;

            return data;
        }
    }
}
