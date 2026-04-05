namespace SharpDTLS
{
    public interface IDatagram
    {
        byte[] Bytes { get; }
        void FromBytes(byte[] bytes);
        byte[] ToBytes();
    }
}
