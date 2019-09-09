using System;

namespace TlsCheck.Tls.Alert
{
    internal class AlertProtocol : Record
    {
        public AlertLevel Level { get; private set; }
        public AlertDescription Description { get; private set; }

        public AlertProtocol() : base()
        {
        }

        public override uint Deserialize(Span<byte> buffer)
        {
            uint byteCount = base.Deserialize(buffer);
            Level = (AlertLevel)buffer[(int)byteCount++];
            Description = (AlertDescription)buffer[(int)byteCount++];
            return byteCount;
        }
    }
}
