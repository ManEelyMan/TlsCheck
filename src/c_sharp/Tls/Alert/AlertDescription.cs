namespace TlsCheck.Tls.Alert
{
    internal enum AlertDescription : byte
    {
        CloseNotify = 0,

        //An inappropriate message was received.  This alert is always fatal
        //and should never be observed in communication between proper
        //implementations.
        UnexpectedMessage = 10,

        //This alert is returned if a record is received with an incorrect
        //MAC.  This alert also MUST be returned if an alert is sent because
        //a TLSCiphertext decrypted in an invalid way: either it wasn't an
        //even multiple of the block length, or its padding values, when
        //checked, weren't correct.  This message is always fatal.
        BadRecordMac = 20,

        //This alert MAY be returned if a TLSCiphertext decrypted in an
        //invalid way: either it wasn't an even multiple of the block
        //length, or its padding values, when checked, weren't correct.
        //This message is always fatal.

        //Note: Differentiating between bad_record_mac and decryption_failed
        //alerts may permit certain attacks against CBC mode as used in
        //TLS [CBCATT].  It is preferable to uniformly use the
        //bad_record_mac alert to hide the specific type of the error.
        DecryptionFailed_RESERVED = 21,

        //A TLSCiphertext record was received that had a length more than
        //2^14+2048 bytes, or a record decrypted to a TLSCompressed
        //record with more than 2^14+1024 bytes.  This message is always
        //fatal.
        RecordOverflow = 22,

        //The decompression function received improper input (e.g., data
        //that would expand to excessive length).  This message is always
        //fatal.
        DecompressionFailure = 30,

        //Reception of a handshake_failure alert message indicates that
        //the sender was unable to negotiate an acceptable set of
        //security parameters given the options available.  This is a
        //fatal error.
        HandshakeFailure = 40,

        //This alert was used in SSLv3 but not in TLS.  It should not be
        //sent by compliant implementations.
        NoCertificate_RESERVED = 41,

        //A certificate was corrupt, contained signatures that did not
        //verify correctly, etc.
        BadCertificate = 42,

        //A certificate was of an unsupported type.
        UnsupportedCertificate = 43,

        //A certificate was revoked by its signer.
        CertificateRevoked = 44,

        //A certificate has expired or is not currently valid.
        CertificateExpired = 45,

        //Some other (unspecified) issue arose in processing the
        //certificate, rendering it unacceptable.
        CertificateUnknown = 46,

        //A field in the handshake was out of range or inconsistent with
        //other fields.  This is always fatal.
        IllegalParameter = 47,

        //A valid certificate chain or partial chain was received, but
        //the certificate was not accepted because the CA certificate
        //could not be located or couldn't be matched with a known,
        //trusted CA.  This message is always fatal.
        UnknownCA = 48,

        //A valid certificate was received, but when access control was
        //applied, the sender decided not to proceed with negotiation.
        //This message is always fatal.
        AccessDenied = 49,

        //A message could not be decoded because some field was out of
        //the specified range or the length of the message was incorrect.
        //This message is always fatal.
        DecodeError = 50,

        //A handshake cryptographic operation failed, including being
        //unable to correctly verify a signature, decrypt a key exchange,
        //or validate a finished message.
        DecryptError = 51,

        //This alert was used in TLS 1.0 but not TLS 1.1.
        ExportRestriction_RESERVED = 60,

        //The protocol version the client has attempted to negotiate is
        //recognized but not supported.  (For example, old protocol
        //versions might be avoided for security reasons).  This message
        //is always fatal.
        ProtocolVersion = 70,

        //Returned instead of handshake_failure when a negotiation has
        //failed specifically because the server requires ciphers more
        //secure than those supported by the client.  This message is
        //always fatal.
        InsufficientSecurity = 71,

        //An internal error unrelated to the peer or the correctness of
        //the protocol(such as a memory allocation failure) makes it
        //impossible to continue.  This message is always fatal.
        InternalError = 80,

        //This handshake is being canceled for some reason unrelated to a
        //protocol failure.  If the user cancels an operation after the
        //handshake is complete, just closing the connection by sending a
        //close_notify is more appropriate.  This alert should be
        //followed by a close_notify.  This message is generally a
        //warning.
        UserCanceled = 90,

        //Sent by the client in response to a hello request or by the
        //server in response to a client hello after initial handshaking.
        //Either of these would normally lead to renegotiation; when that
        //is not appropriate, the recipient should respond with this
        //alert.  At that point, the original requester can decide
        //whether to proceed with the connection.  One case where this
        //would be appropriate is where a server has spawned a process to
        //satisfy a request; the process might receive security
        //parameters (key length, authentication, etc.) at startup and it
        //might be difficult to communicate changes to these parameters
        //after that point.  This message is always a warning.        
        NoRenegotiation = 100,

        UnsupportedExtension = 110
    }
}
