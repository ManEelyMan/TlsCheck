using System;
using System.Collections.Generic;
using System.Text;
using TlsCheck.Tls.Alert;
using TlsCheck.Tls.Handshake;

namespace TlsCheck.Tls
{
    internal class RecordFactory
    {
        public static Record Create(Span<byte> bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            if (bytes.Length < 5) throw new ArgumentException("A minimum of 5 bytes is needed to parse a TLS record.");

            RecordContentTypes type = (RecordContentTypes)bytes[0];

            switch (type)
            {
                case RecordContentTypes.Alert:
                    AlertProtocol alertRecord = new AlertProtocol();
                    alertRecord.Deserialize(bytes);
                    return alertRecord;

                case RecordContentTypes.ApplicationData:
                    throw new NotImplementedException("Can't yet handle 'Application Data' content.");

                case RecordContentTypes.ChangeCipherSpec:
                    throw new NotImplementedException("Can't yet handle 'Change Cipher Spec' content.");

                case RecordContentTypes.Handshake:
                    HandshakeType handshakeType = (HandshakeType)bytes[5];
                    switch (handshakeType)
                    {
                        case HandshakeType.ServerHello:
                            ServerHello serverHello = new ServerHello();
                            serverHello.Deserialize(bytes);
                            return serverHello;

                        default:
                            throw new NotImplementedException($"Can't yet handle 'Handshake' content of type '{handshakeType}'.");
                    }

                default:
                    throw new ArgumentException($"Unknown record content type: {type}");
            }
        }
    }
}
