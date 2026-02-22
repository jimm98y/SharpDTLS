namespace Dtls13Test.Messages
{
    public interface IDatagram
    {
        byte[] Bytes { get; }
        void FromBytes(byte[] bytes);
        byte[] ToBytes();
    }
}
