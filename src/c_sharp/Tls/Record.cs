using System;

namespace TlsCheck.Tls
{
    public abstract class Record
    {
        public RecordContentTypes ContentType { get; set; }
        public ProtocolVersion ProtocolVersion { get; set; }
        public ushort RecordLength { get; set; }

        public Record() { }

        public Record(RecordContentTypes contentType, ProtocolVersion protocolVersion)
        {
            this.ContentType = contentType;
            this.ProtocolVersion = protocolVersion;
        }

        public virtual uint Deserialize(Span<byte> buffer)
        {
            this.ContentType = (RecordContentTypes)buffer[0];
            this.ProtocolVersion = (ProtocolVersion)buffer.Slice(1).ReadUShort();
            this.RecordLength = buffer.Slice(3).ReadUShort();
            return 5;
        }

        public virtual uint Serialize(Span<byte> buffer)
        {
            uint byteCount = 0;

            buffer[(int)byteCount++] = (byte)ContentType;
            byteCount += buffer.Slice(byteCount).WriteUShort((ushort)ProtocolVersion);

            // We're going to use the entire buffer allocated.
            // Subtract 5 bytes for the content type, protocol version, and length fields here and above.
            byteCount += buffer.Slice(byteCount).WriteUShort((ushort)(buffer.Length - 5));

            return byteCount;
        }
    }
}
