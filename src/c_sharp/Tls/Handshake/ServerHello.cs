using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace TlsCheck.Tls.Handshake
{
    internal sealed class ServerHello : HandshakeProtocol
    {
        public CipherSuites CipherSuite { get; private set; }
        public IReadOnlyCollection<ExtensionTypes> Extensions { get; private set; }

        public ServerHello() : base() { }

        public override uint Deserialize(Span<byte> buffer)
        {
            uint byteCount = base.Deserialize(buffer);

            Span<byte> random = buffer.Slice(byteCount, 32);
            byteCount += 32;

            byte sessionIdLength = buffer[(int)byteCount++];
            Span<byte> sessionId = buffer.Slice(byteCount, sessionIdLength);
            byteCount += sessionIdLength;

            this.CipherSuite = (CipherSuites)buffer.Slice(byteCount).ReadUShort();
            byteCount += 2;

            byte compressionMethod = buffer[(int)byteCount++];

            ushort extensionsLength = buffer.Slice(byteCount).ReadUShort();
            byteCount += 2;

            this.Extensions = this.DeserializeExtensions(buffer.Slice(byteCount, extensionsLength)).ToArray();

            return byteCount + extensionsLength;
        }

        public override uint Serialize(Span<byte> buffer)
        {
            // We're the client so we'll never send a ServerHello.
            throw new NotImplementedException();
        }

        private IEnumerable<ExtensionTypes> DeserializeExtensions(Span<byte> buffer)
        {
            int currByte = 0;
            List<ExtensionTypes> types = new List<ExtensionTypes>();

            while(currByte < buffer.Length)
            {
                // Get the extension type value
                ExtensionTypes type = (ExtensionTypes)buffer.Slice(currByte).ReadUShort();
                currByte += 2;
                types.Add(type);

                // Get the length (in bytes) of this extension
                ushort extensionLength = buffer.Slice(currByte).ReadUShort();
                currByte += 2;

                // We don't need the extension's info, so just skip the data.
                currByte += extensionLength;
            }

            return types;
        }
    }
}
