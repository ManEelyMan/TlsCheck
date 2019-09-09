namespace TlsCheck.Tls
{
    public enum RecordContentTypes : byte
    {
        ChangeCipherSpec = 20,
        Alert = 21,
        Handshake = 22,
        ApplicationData = 23
    }
}
