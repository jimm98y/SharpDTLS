namespace Dtls13Test.Messages
{
    public interface IMessage
    {
        void FromBytes(byte[] bytes);
        byte[] ToBytes();
    }
}
