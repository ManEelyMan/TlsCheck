namespace TlsCheck.Tls.Handshake
{
    /// <summary>
    /// The most recent (as of 08-16-2019) list of TLS Extensions, per IANA:
    /// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#tls-extensiontype-values-1
    /// </summary>
    internal enum ExtensionTypes : ushort
    {
        server_name = 0,
        max_fragment_length = 1,
        client_certificate_url = 2,
        trusted_ca_keys = 3,
        truncated_hmac = 4,
        status_request = 5,
        user_mapping = 6,
        client_authz = 7,
        server_authz = 8,
        cert_type = 9,
        supported_groups = 10, //(renamed from "elliptic_curves")
        ec_point_formats = 11,
        srp = 12,
        signature_algorithms = 13,
        use_srtp = 14,
        heartbeat = 15,
        application_layer_protocol_negotiation = 16,
        status_request_v2 = 17,
        signed_certificate_timestamp = 18,
        client_certificate_type = 19,
        server_certificate_type = 20,
        padding = 21,
        encrypt_then_mac = 22,
        extended_master_secret = 23,
        token_binding = 24,
        cached_info = 25,
        tls_lts = 26,
        compress_certificate = 27, //"(TEMPORARY - registered 2018-05-23, extension registered 2019-04-22, expires 2020-05-23)"
        record_size_limit = 28,
        pwd_protect = 29,
        pwd_clear = 30,
        password_salt = 31,
        ticket_pinning = 32,
        /* 33-34	Unassigned */
        session_ticket = 35, //(renamed from "SessionTicket TLS")
        /* 36-40	Unassigned */
        pre_shared_key = 41,
        early_data = 42,
        supported_versions = 43,
        cookie = 44,
        psk_key_exchange_modes = 45,
        Unassigned = 46,
        certificate_authorities = 47,
        oid_filters = 48,
        post_handshake_auth = 49,
        signature_algorithms_cert = 50,
        key_share = 51,
        transparency_info = 52,
        connection_id = 53, // "(TEMPORARY - registered 2019-07-02, expires 2020-07-02)"
        Unassigned2 = 54,
        external_id_hash = 55,
        external_session_id = 56,
        /* 57-65279	Unassigned */
        Reserved = 65280, // for Private Use
        renegotiation_info = 65281
        /* 65282-65535	Reserved for Private Use */
    }
}
