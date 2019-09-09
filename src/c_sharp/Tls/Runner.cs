using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Threading.Tasks;
using TlsCheck.Tls.Handshake;

namespace TlsCheck.Tls
{
    internal static class Runner
    {
        private const int MaxRecordSizeInBytes = 517; // TODO: Have this configurable in case this isn't big enough.
        private const int ServerReadTimeoutInSeconds = 3; // TODO: Have this configurable in case this isn't big enough.

        public static async Task<IEnumerable<ProtocolVersion>> GetSupportedProtocolVersionsAsync(string hostName, int port = 443)
        {
            List<ProtocolVersion> supportedVersions = new List<ProtocolVersion>();

            foreach (var version in Enum.GetValues(typeof(ProtocolVersion)).Cast<ProtocolVersion>())
            {
                Record response = await SendClientHelloAsync(TlsRequestParameters.Create(hostName, port, version, version, null));

                bool supported = response.ContentType == RecordContentTypes.Handshake;
                if (supported)
                {
                    supportedVersions.Add(version);
                }
            }

            return supportedVersions;
        }

        public static async Task<IEnumerable<CipherSuites>> GetSupportedCipherSuitesAsync(string hostName, int port = 443, ProtocolVersion protocolVersion = ProtocolVersion.Tls12)
        {
            List<CipherSuites> supportedCipherSuites = new List<CipherSuites>();

            foreach (CipherSuites suite in Enum.GetValues(typeof(CipherSuites)).Cast<CipherSuites>())
            {
                Record response = await SendClientHelloAsync(TlsRequestParameters.Create(hostName, port, protocolVersion, protocolVersion, new CipherSuites[] { suite }));
                if (response == null) throw new Exception("No response received from server. Check the host name and port number.");

                bool supported = response.ContentType == RecordContentTypes.Handshake;
                if (supported)
                {
                    supportedCipherSuites.Add(suite);
                }
            }

            return supportedCipherSuites;
        }

        private static async Task<Record> SendClientHelloAsync(TlsRequestParameters requestParameters)
        {
            if (requestParameters.CipherSuites == null)
            {
                requestParameters.CipherSuites = new CipherSuites[]
                {
                    Tls.CipherSuites.TLS_AES_128_GCM_SHA256,
                    Tls.CipherSuites.TLS_AES_256_GCM_SHA384,
                    Tls.CipherSuites.TLS_CHACHA20_POLY1305_SHA256,
                    Tls.CipherSuites.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                    Tls.CipherSuites.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    Tls.CipherSuites.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                    Tls.CipherSuites.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                    Tls.CipherSuites.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                    Tls.CipherSuites.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                    Tls.CipherSuites.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                    Tls.CipherSuites.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                    Tls.CipherSuites.TLS_RSA_WITH_AES_128_GCM_SHA256,
                    Tls.CipherSuites.TLS_RSA_WITH_AES_256_GCM_SHA384,
                    Tls.CipherSuites.TLS_RSA_WITH_AES_128_CBC_SHA,
                    Tls.CipherSuites.TLS_RSA_WITH_AES_256_CBC_SHA,
                    Tls.CipherSuites.TLS_RSA_WITH_3DES_EDE_CBC_SHA
                };
            }

            using (TcpClient client = new TcpClient())
            {
                await client.ConnectAsync(requestParameters.Host, requestParameters.Port);

                NetworkStream s = client.GetStream();
                s.ReadTimeout = ServerReadTimeoutInSeconds * 1000;

                ClientHello hello = new ClientHello(
                    requestParameters.HandshakeVersion,
                    requestParameters.CipherSuites,
                    requestParameters.RecordVersion);

                await WriteRecordToStringAsync(hello, s);

                return await HandleResponse(s, requestParameters);
            }
        }

        private static async Task<Record> HandleResponse(NetworkStream s, TlsRequestParameters requestParameters)
        {
            byte[] buffer = new byte[1024];
            int bytesRead = await s.ReadAsync(buffer, 0, 1024);

            if (bytesRead <= 0)
            {
                Console.WriteLine("Not enough data! :O ");
                return null;
            }

            return RecordFactory.Create(new Span<byte>(buffer));
        }

        private static async Task WriteRecordToStringAsync(Record record, Stream destination)
        {
            byte[] buffer = new byte[MaxRecordSizeInBytes];
            uint byteCount = record.Serialize(new Span<byte>(buffer));
            await destination.WriteAsync(buffer, 0, (int)byteCount);
        }
    }
}
