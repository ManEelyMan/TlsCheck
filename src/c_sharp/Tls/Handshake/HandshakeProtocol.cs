using System;

namespace TlsCheck.Tls.Handshake
{
    /// <summary>
    /// Base class for all records in the TLS Handshake Protocol.
    /// </summary>
    public abstract class HandshakeProtocol : Record
    {
        /// <summary>
        /// The type of handshake record. See <see cref="HandshakeType"/>.
        /// </summary>
        public HandshakeType HandshakeType { get; private set; }

        /// <summary>
        ///  The protocol version this handshake uses. See <see cref="ProtocolVersion"/>.
        /// </summary>
        public ProtocolVersion HandshakeProtocolVersion { get; private set; }

        public HandshakeProtocol() { }

        public HandshakeProtocol(
            HandshakeType handshakeType,
            ProtocolVersion handshakeProtocolVersion, 
            ProtocolVersion? recordProtocolVersion = null) : base (
                RecordContentTypes.Handshake, 
                recordProtocolVersion ?? handshakeProtocolVersion)
        {
            this.HandshakeType = handshakeType;
            this.HandshakeProtocolVersion = this.HandshakeProtocolVersion;
        }

        public override uint Deserialize(Span<byte> buffer)
        {
            uint byteCount = base.Deserialize(buffer);

            this.HandshakeType = (HandshakeType)buffer[(int)byteCount++];

            // Get the length.
            byteCount++; // Skip the next byte. It's the highest-order byte of a 3-byte integer which is always unused.
            uint handshakeLength = buffer.Slice(byteCount).ReadUShort();
            byteCount += 2;

            this.HandshakeProtocolVersion = (ProtocolVersion)buffer.Slice(byteCount).ReadUShort();
            byteCount += 2;

            return byteCount;
        }

        public override uint Serialize(Span<byte> buffer)
        {
            uint byteCount = base.Serialize(buffer);

            // Client Hello Type
            buffer[(int)byteCount++] = (byte)HandshakeType;

            // Length of Client Hello (3 byte big-endian, first byte always 0.)
            buffer[(int)byteCount++] = 0;
            byteCount += buffer.Slice(byteCount).WriteUShort((ushort)(buffer.Length - byteCount - 2));

            // Handshake version
            byteCount += buffer.Slice(byteCount).WriteUShort((ushort)ProtocolVersion);

            return byteCount;
        }
    }
}
