using System;
using System.Collections.Generic;
using System.IO;

namespace TlsCheck.Tls.Handshake
{
    /// <summary>
    /// A handshake client hello record.
    /// </summary>
    internal sealed class ClientHello : HandshakeProtocol
    {
        // This should be large enough for our purposes. Make it dynamic/configurable in the future?
        private const int ClientHelloRecordSize = 517;

        /// <summary>
        /// The CipherSuites to declare the client supports. See <see cref="CipherSuites"/>.
        /// </summary>
        public IReadOnlyCollection<CipherSuites> CipherSuites { get; set; }

        public ClientHello(
            ProtocolVersion handshakeProtocolVersion,
            IReadOnlyCollection<CipherSuites> cipherSuites,
            ProtocolVersion? recordProtocolVersion = null) : base(
                HandshakeType.ClientHello, 
                handshakeProtocolVersion, 
                recordProtocolVersion ?? handshakeProtocolVersion)
        {
            this.CipherSuites = cipherSuites ?? throw new ArgumentNullException(nameof(cipherSuites));
        }

        public override uint Deserialize(Span<byte> buffer)
        {
            // As the client, we should never receive a ClientHello.
            throw new NotImplementedException();
        }

        public override uint Serialize(Span<byte> buffer)
        {
            uint byteCount = base.Serialize(buffer);

            // Random timestamp
            byteCount += buffer.Slice(byteCount).WriteUInt(Utilities.GetUnixSystemTimeUtc()); //Random timestamp

            // Random bytes
            byteCount += buffer.Slice(byteCount).WriteBytes(Utilities.GetRandomBytes(28));

            // Session ID length followed by the ID itself.
            buffer[(int)byteCount++] = 32;
            byteCount += buffer.Slice(byteCount).WriteBytes(Utilities.GetRandomBytes(32));

            // Cipher Suites
            byteCount += WriteCipherSuites(buffer.Slice(byteCount));

            // Compression method
            buffer[(int)byteCount++] = 1;  // Length.
            buffer[(int)byteCount++] = 0;  // Method = null

            // Extensions
            byteCount += WriteExtensions(buffer.Slice(byteCount));

            return byteCount;
        }

        private uint WriteCipherSuites(Span<byte> buffer)
        {
            uint byteCount = 0;

            ushort length = (ushort)((CipherSuites?.Count ?? 0) * 2);
            byteCount += buffer.WriteUShort(length);

            if (CipherSuites == null) return byteCount;

            foreach (var cipherSuite in CipherSuites)
            {
                byteCount += buffer.Slice(byteCount).WriteUShort((ushort)cipherSuite);
            }

            return byteCount;
        }

        private static uint WriteExtensions(Span<byte> buffer)
        {
            // The size of this length field. 
            // Our final padding extension is going to write all the way to the end of our buffer. 
            // So the size of the extension block will be whatever the size of the remaining buffer, minus the bytes for the length itself (2).
            ushort extensionsLength = (ushort)(buffer.Length - 2);

            uint byteCount = 0;
            byteCount += buffer.Slice(byteCount).WriteUShort(extensionsLength); // Extensions Length

            // Write out all of our extensions. 

            // TODO:
            //       1. Figure out what extensions are actually needed. I just took these from what I saw Chrome doing in Wireshark.
            //       2. Create a way for these to be dynamically selected like with the cipher suites. 
            //          This could be harder because extra information might be needed for each extension (e.g. server_name)
            byteCount += Extensions.WriteExtendedMasterSecretExtensionTo(buffer.Slice(byteCount));
            byteCount += Extensions.WriteRenegotiationInfoExtensionTo(buffer.Slice(byteCount));
            byteCount += Extensions.WriteSupportedGroupsExtensionTo(buffer.Slice(byteCount));
            byteCount += Extensions.WriteSupportedPointFormatsExtensionTo(buffer.Slice(byteCount));
            byteCount += Extensions.WriteSessionTicketTlsExtensionTo(buffer.Slice(byteCount));
            byteCount += Extensions.WriteApplicationLayerProtocolNegotiatonExtensionTo(buffer.Slice(byteCount));
            byteCount += Extensions.WriteStatusRequestExtensionTo(buffer.Slice(byteCount));
            byteCount += Extensions.WriteSignatureAlgorithmsExtensionTo(buffer.Slice(byteCount));
            byteCount += Extensions.WriteSignedCertificateTimestampExtensionTo(buffer.Slice(byteCount));
            byteCount += Extensions.WriteKeyShareExtensionTo(buffer.Slice(byteCount));
            byteCount += Extensions.WritePskKeyExchangeModesExtensionTo(buffer.Slice(byteCount));
            byteCount += Extensions.WriteSupportedVersionsExtensionTo(buffer.Slice(byteCount));
            byteCount += Extensions.WriteCompressCertificateExtensionTo(buffer.Slice(byteCount));
            byteCount += Extensions.WritePaddingExtensionTo(buffer.Slice(byteCount));
            return byteCount;
        }

        public static void WriteToStream(Stream destination,
            IReadOnlyCollection<CipherSuites> cipherSuites,
            ProtocolVersion recordVersion = ProtocolVersion.Tls12,
            ProtocolVersion handshakeVersion = ProtocolVersion.Tls12)
        {
            Span<byte> buffer = new Span<byte>(new byte[ClientHelloRecordSize]);

            ClientHello hello = new ClientHello(handshakeVersion, cipherSuites, recordVersion);
            uint byteCount = hello.Serialize(buffer);

            buffer.PrintToConsole("Client Hello:", byteCount);
            destination.Write(buffer.ToArray(), 0, (int)byteCount);
        }
    }
}
