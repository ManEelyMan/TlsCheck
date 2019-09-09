using System;
using System.Linq;

namespace TlsCheck.Tls.Handshake
{
    /// <summary>
    /// Static class that writes extension information for a client hello record.
    /// </summary>
    internal static class Extensions
    {
        public static uint WriteServerNameExtensionTo(Span<byte> s, string name)
        {
            uint byteCount = 0;
            byteCount += s.Slice(byteCount).WriteUShort((ushort)ExtensionTypes.server_name);
            byteCount += s.Slice(byteCount).WriteUShort((ushort)(name.Length + 5)); // Length of ServerList structure.
            byteCount += s.Slice(byteCount).WriteUShort((ushort)(name.Length + 3)); // Length of ServerName structure.
            s[(int)byteCount++] = 0; // ServerName type: host_name
            byteCount += s.Slice(byteCount).WriteString(name);
            return byteCount;
        }

        public static uint WriteExtendedMasterSecretExtensionTo(Span<byte> s)
        {
            uint byteCount = 0;
            byteCount += s.Slice(byteCount).WriteUShort((ushort)ExtensionTypes.extended_master_secret);
            byteCount += s.Slice(byteCount).WriteUShort(0x00); // Length.
            return byteCount;
        }

        public static uint WriteRenegotiationInfoExtensionTo(Span<byte> s)
        {
            uint byteCount = 0;
            byteCount += s.Slice(byteCount).WriteUShort((ushort)ExtensionTypes.renegotiation_info);
            byteCount += s.Slice(byteCount).WriteUShort(0x01); // Length.
            s[(int)byteCount++] = 0; // Renegotiation info length.
            return byteCount;
        }

        public static uint WriteSupportedGroupsExtensionTo(Span<byte> s)
        {
            uint byteCount = 0;
            byteCount += s.Slice(byteCount).WriteUShort((ushort)ExtensionTypes.supported_groups);
            byteCount += s.Slice(byteCount).WriteUShort(10); // Extension length
            byteCount += s.Slice(byteCount).WriteUShort(0x0008); // Supported Groups List length
            byteCount += s.Slice(byteCount).WriteUShort(0x0017); // secp256r1
            byteCount += s.Slice(byteCount).WriteUShort(0x0018); // secp384r1
            byteCount += s.Slice(byteCount).WriteUShort(0x001D); // x25519
            byteCount += s.Slice(byteCount).WriteUShort(0x001E); // x448
            return byteCount;
        }

        public static uint WriteSupportedPointFormatsExtensionTo(Span<byte> s)
        {
            uint byteCount = 0;
            byteCount += s.Slice(byteCount).WriteUShort((ushort)ExtensionTypes.ec_point_formats);
            byteCount += s.Slice(byteCount).WriteUShort(0x02); // Extension length
            s[(int)byteCount++] = 01; // EC Point formats length
            s[(int)byteCount++] = 00; // Uncompressed
            return byteCount;
        }

        public static uint WriteSessionTicketTlsExtensionTo(Span<byte> s)
        {
            uint byteCount = 0;
            byteCount += s.Slice(byteCount).WriteUShort((ushort)ExtensionTypes.session_ticket);
            byteCount += s.Slice(byteCount).WriteUShort(0x0000); // Length
            return byteCount;
        }

        public static uint WriteApplicationLayerProtocolNegotiatonExtensionTo(Span<byte> s)
        {
            uint byteCount = 0;
            byteCount += s.Slice(byteCount).WriteUShort((ushort)ExtensionTypes.application_layer_protocol_negotiation);
            byteCount += s.Slice(byteCount).WriteUShort(0x000E); // Extension length
            byteCount += s.Slice(byteCount).WriteUShort(0x000C); // ALPN Extension length
            s[(int)byteCount++] = 02; // String Length;
            byteCount += s.Slice(byteCount).WriteString("h2");
            s[(int)byteCount++] = 08; //String length;
            byteCount += s.Slice(byteCount).WriteString("http/1.1");
            return byteCount;
        }

        public static uint WriteStatusRequestExtensionTo(Span<byte> s)
        {
            uint byteCount = 0;
            byteCount += s.Slice(byteCount).WriteUShort((ushort)ExtensionTypes.status_request);
            byteCount += s.Slice(byteCount).WriteUShort(0x005); // Length.
            s[(int)byteCount++] = 01; // Certificate status Type: OCSP.
            byteCount += s.Slice(byteCount).WriteUShort(0x0000); // Respond ID list length
            byteCount += s.Slice(byteCount).WriteUShort(0x0000); // Request Extensions Length
            return byteCount;
        }

        public static uint WriteSignatureAlgorithmsExtensionTo(Span<byte> s)
        {
            uint byteCount = 0;
            byteCount += s.Slice(byteCount).WriteUShort((ushort)ExtensionTypes.signature_algorithms);
            byteCount += s.Slice(byteCount).WriteUShort(0x0022); // Length
            byteCount += s.Slice(byteCount).WriteUShort(0x0020); // Signature Hash Algorthms Length

            /* RSASSA-PKCS1-v1_5 algorithms */
            byteCount += s.Slice(byteCount).WriteUShort(0x0401); // rsa_pkcs1_sha256
            byteCount += s.Slice(byteCount).WriteUShort(0x0501); // rsa_pkcs1_sha384
            byteCount += s.Slice(byteCount).WriteUShort(0x0601); // rsa_pkcs1_sha512

            /* ECDSA algorithms */
            byteCount += s.Slice(byteCount).WriteUShort(0x0403); // ecdsa_secp256r1_sha256
            byteCount += s.Slice(byteCount).WriteUShort(0x0503); // ecdsa_secp384r1_sha384
            byteCount += s.Slice(byteCount).WriteUShort(0x0603); // ecdsa_secp521r1_sha512

            /* RSASSA-PSS algorithms with public key OID rsaEncryption */
            byteCount += s.Slice(byteCount).WriteUShort(0x0804); // rsa_pss_rsae_sha256
            byteCount += s.Slice(byteCount).WriteUShort(0x0805); // rsa_pss_rsae_sha384
            byteCount += s.Slice(byteCount).WriteUShort(0x0806); // rsa_pss_rsae_sha512

            /* EdDSA algorithms */
            byteCount += s.Slice(byteCount).WriteUShort(0x0807); // ed25519
            byteCount += s.Slice(byteCount).WriteUShort(0x0808); // ed448

            /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
            byteCount += s.Slice(byteCount).WriteUShort(0x0809); // rsa_pss_pss_sha256
            byteCount += s.Slice(byteCount).WriteUShort(0x080a); // rsa_pss_pss_sha384
            byteCount += s.Slice(byteCount).WriteUShort(0x080b); // rsa_pss_pss_sha512

            /* Legacy algorithms */
            byteCount += s.Slice(byteCount).WriteUShort(0x0201); // rsa_pkcs1_sha1
            byteCount += s.Slice(byteCount).WriteUShort(0x0203); // ecdsa_sha1             

            return byteCount;
        }

        public static uint WriteSignedCertificateTimestampExtensionTo(Span<byte> s)
        {
            uint byteCount = 0;
            byteCount += s.Slice(byteCount).WriteUShort((ushort)ExtensionTypes.signed_certificate_timestamp);
            byteCount += s.Slice(byteCount).WriteUShort(0x0000); // Length.
            return byteCount;
        }

        public static uint WriteKeyShareExtensionTo(Span<byte> s)
        {
            uint byteCount = 0;
            byteCount += s.Slice(byteCount).WriteUShort((ushort)ExtensionTypes.key_share);
            byteCount += s.Slice(byteCount).WriteUShort(0x002B); //Length.
            byteCount += s.Slice(byteCount).WriteBytes(Utilities.GetRandomBytes(43));
            return byteCount;
        }

        public static uint WritePskKeyExchangeModesExtensionTo(Span<byte> s)
        {
            uint byteCount = 0;
            byteCount += s.Slice(byteCount).WriteUShort((ushort)ExtensionTypes.psk_key_exchange_modes);
            byteCount += s.Slice(byteCount).WriteUShort(0x0002); // Length.
            s[(int)byteCount++] = 01; // PSK Key Exchange Modes Length
            s[(int)byteCount++] = 01; // PSK Key Exchange Mode: PSK with (EC)DHE key establishment
            return byteCount;
        }

        public static uint WriteSupportedVersionsExtensionTo(Span<byte> s)
        {
            uint byteCount = 0;
            byteCount += s.Slice(byteCount).WriteUShort((ushort)ExtensionTypes.supported_versions);
            byteCount += s.Slice(byteCount).WriteUShort(0x000B); // Length.
            s[(int)byteCount++] = 10; // Supported Versions Length
            byteCount += s.Slice(byteCount).WriteUShort(0x0300); // SSL v3.0
            byteCount += s.Slice(byteCount).WriteUShort(0x0301); // TLS v1.0
            byteCount += s.Slice(byteCount).WriteUShort(0x0302); // TLS v1.1
            byteCount += s.Slice(byteCount).WriteUShort(0x0303); // TLS v1.2
            byteCount += s.Slice(byteCount).WriteUShort(0x0304); // TLS v1.3
            return byteCount;
        }

        public static uint WriteCompressCertificateExtensionTo(Span<byte> s)
        {
            uint byteCount = 0;
            byteCount += s.Slice(byteCount).WriteUShort((ushort)ExtensionTypes.compress_certificate);
            byteCount += s.Slice(byteCount).WriteUShort(0x0003); // Length
            byteCount += s.Slice(byteCount).WriteBytes(Utilities.ConvertHexStringToBytes("020002").ToArray()); // Not really sure what these bytes mean.  :/
            return byteCount;
        }

        /// <summary>
        /// Writes a "padding" extension to consume the rest of the allocated buffer.
        /// </summary>
        /// <param name="s">The <see cref="Span{T}"/> to write to.</param>
        /// <returns>The number of bytes written to the span.</returns>
        public static uint WritePaddingExtensionTo(Span<byte> s)
        {
            // Final "extension" is padding.
            uint byteCount = 0;
            byteCount += s.Slice(byteCount).WriteUShort((ushort)ExtensionTypes.padding);

            // Determine number of padding bytes.
            ushort remainingBytes = (ushort)(s.Length - byteCount - 2); // 2 = the next 2 bytes for the extension's length.

            // Length of padding extention.
            byteCount += s.Slice(byteCount).WriteUShort(remainingBytes);

            // Padding bytes themselves.
            Span<byte> paddingExtData = s.Slice(byteCount);
            for (int i = 0; i < remainingBytes; i++) paddingExtData[i] = 0;

            return byteCount + remainingBytes;
        }
    }
}
