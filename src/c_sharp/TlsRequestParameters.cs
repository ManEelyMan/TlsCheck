using System;
using System.Collections.Generic;
using System.Text;
using TlsCheck.Tls;

namespace TlsCheck
{
    internal class TlsRequestParameters
    {
        public string Host { get; set; }
        public int Port { get; set; }
        public ProtocolVersion RecordVersion { get; set; }
        public ProtocolVersion HandshakeVersion { get; set; }
        public IReadOnlyCollection<CipherSuites> CipherSuites { get; set; }

        public static TlsRequestParameters Create(string host, int port, ProtocolVersion recordVersion, ProtocolVersion handshakeVersion, IReadOnlyCollection<CipherSuites> cipherSuites)
        {
            return new TlsRequestParameters()
            {
                Host = host,
                Port = port,
                RecordVersion = recordVersion,
                HandshakeVersion = handshakeVersion,
                CipherSuites = cipherSuites
            };
        }
    }
}
