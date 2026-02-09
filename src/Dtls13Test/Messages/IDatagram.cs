namespace Dtls13Test.Messages
{
    public interface IDatagram
    {
        void FromBytes(byte[] bytes);
        byte[] ToBytes();
    }
}
