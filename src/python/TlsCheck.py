import calendar
import os
import socket
import sys
import time

def main(args):

    if len(args) < 3:
        usage()
        return

    host = args[1]
    port = int(args[2])

    print("Testing TLS configuration of %s:%d...\n" % (host, port))

    print("Supported versions of SSL/TLS:")
    test_protocol_versions(host, port)

    print("\nSupported cipher suites:")
    test_cipher_suites(host, port)

def usage():
    print("python TlsCheck.py <host> <port>")

def send_client_hello(host, port, protocolVersionHex, cipherSuiteHex):

    unixEpochTime = calendar.timegm(time.gmtime())
    unixEpochTimeHex = hex(unixEpochTime)

    cipherSuiteLengthInBytes = len(cipherSuiteHex) // 2
    cipherSuiteLengthHex = "{0:#0{1}x}".format(cipherSuiteLengthInBytes,6)[2:]

    extensionsLength = 517 - (5 + 6 + 32 + 1 + 32 + 2 + 2 + 2 + cipherSuiteLengthInBytes)  # Packet size minus all parts preceeding the extensions block.
    extensionsLengthHex = "{0:#0{1}x}".format(extensionsLength,6)[2:]

    paddingLength = extensionsLength - 172 - 4 # Size of extensions - preceeding data and extension type and length bytes.
    paddingLengthHex = "{0:#0{1}x}".format(paddingLength,6)[2:]

    clientHelloHex = (
    '16' + protocolVersionHex + '0200' +             # TLS Record Layer
    '010001fc' + protocolVersionHex +                # Handshake Protocol: Client Hello
    unixEpochTimeHex[2:] +                           # Unix Epoch Time (removing the '0x' from the front)
    os.urandom(28).hex() +                           # 28 random bytes
    '20' +                                           # Session Id size
    os.urandom(32).hex() +                           # 32 random bytes for the session id
    cipherSuiteLengthHex +                           # Length of cipher suites
    cipherSuiteHex +                                 # Cipher suites
    '0100' +                                         # Compression method (null)
    extensionsLengthHex +                            # Extensions section length
    '7a7a000000170000ff01000100000a00' +             # Extensions (static list of typical ones)
    '0a00080a0a001d00170018000b000201' + 
    '00002300000010000e000c0268320868' + 
    '7474702f312e31000500050100000000' + 
    '000d0014001204030804040105030805' + 
    '0501080606010201001200000033002b' + 
    '00290a0a000100001d0020ee20b0cb4e' + 
    'c74201dc61ef3fab2476663fc3eb85be' + 
    'ed75f0ab9035769d2d7f1b002d000201' + 
    '01002b000b0a0a0a0304030303020301' + 
    '001b0003020002eaea000100' + 
    '0015' +                                         # Padding Extension
    paddingLengthHex +                               # Padding Extension Length
    ('0' * (paddingLength*2)))                       # Padding Data

    request = bytes.fromhex(clientHelloHex)

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host, port))
    client.send(request)

    response = client.recv(4096)
    client.close()

    return response

def test_protocol_versions(host, port):

    protocol_versions = [
        ("0300", "Ssl30"),
        ("0301", "Tls10"), 
        ("0302", "Tls11"),
        ("0303", "Tls12"),
        ("0304", "Tls13")]

    for protocol_version in protocol_versions:

        (hex, description) = protocol_version
        response = send_client_hello(host, port, hex, '6a6a130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035000a')

        if (int(response[0]) == 22): # Check for Server Hello response. Else, assume error.
            print(description)

def test_cipher_suites(host, port):

    cipher_suites = [
        ('0000', 'TLS_NULL_WITH_NULL_NULL'),
        ('0001', 'TLS_RSA_WITH_NULL_MD5'),
        ('0002', 'TLS_RSA_WITH_NULL_SHA'),
        ('0003', 'TLS_RSA_EXPORT_WITH_RC4_40_MD5'),
        ('0004', 'TLS_RSA_WITH_RC4_128_MD5'),
        ('0005', 'TLS_RSA_WITH_RC4_128_SHA'),
        ('0006', 'TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5'),
        ('0007', 'TLS_RSA_WITH_IDEA_CBC_SHA'),
        ('0008', 'TLS_RSA_EXPORT_WITH_DES40_CBC_SHA'),
        ('0009', 'TLS_RSA_WITH_DES_CBC_SHA'),
        ('000A', 'TLS_RSA_WITH_3DES_EDE_CBC_SHA'),
        ('000B', 'TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA'),
        ('000C', 'TLS_DH_DSS_WITH_DES_CBC_SHA'),
        ('000D', 'TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA'),
        ('000E', 'TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA'),
        ('000F', 'TLS_DH_RSA_WITH_DES_CBC_SHA'),
        ('0010', 'TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA'),
        ('0011', 'TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA'),
        ('0012', 'TLS_DHE_DSS_WITH_DES_CBC_SHA'),
        ('0013', 'TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA'),
        ('0014', 'TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA'),
        ('0015', 'TLS_DHE_RSA_WITH_DES_CBC_SHA'),
        ('0016', 'TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA'),
        ('0017', 'TLS_DH_anon_EXPORT_WITH_RC4_40_MD5'),
        ('0018', 'TLS_DH_anon_WITH_RC4_128_MD5'),
        ('0019', 'TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA'),
        ('001A', 'TLS_DH_anon_WITH_DES_CBC_SHA'),
        ('001B', 'TLS_DH_anon_WITH_3DES_EDE_CBC_SHA'),
        # 0x001C, Reserved to avoid conflicts with SSLv3,,, [RFC5246],
        # 0x001D, Reserved to avoid conflicts with SSLv3,,, [RFC5246],
        ('001E', 'TLS_KRB5_WITH_DES_CBC_SHA'),
        ('001F', 'TLS_KRB5_WITH_3DES_EDE_CBC_SHA'),
        ('0020', 'TLS_KRB5_WITH_RC4_128_SHA'),
        ('0021', 'TLS_KRB5_WITH_IDEA_CBC_SHA'),
        ('0022', 'TLS_KRB5_WITH_DES_CBC_MD5'),
        ('0023', 'TLS_KRB5_WITH_3DES_EDE_CBC_MD5'),
        ('0024', 'TLS_KRB5_WITH_RC4_128_MD5'),
        ('0025', 'TLS_KRB5_WITH_IDEA_CBC_MD5'),
        ('0026', 'TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA'),
        ('0027', 'TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA'),
        ('0028', 'TLS_KRB5_EXPORT_WITH_RC4_40_SHA'),
        ('0029', 'TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5'),
        ('002A', 'TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5'),
        ('002B', 'TLS_KRB5_EXPORT_WITH_RC4_40_MD5'),
        ('002C', 'TLS_PSK_WITH_NULL_SHA'),
        ('002D', 'TLS_DHE_PSK_WITH_NULL_SHA'),
        ('002E', 'TLS_RSA_PSK_WITH_NULL_SHA'),
        ('002F', 'TLS_RSA_WITH_AES_128_CBC_SHA'),
        ('0030', 'TLS_DH_DSS_WITH_AES_128_CBC_SHA'),
        ('0031', 'TLS_DH_RSA_WITH_AES_128_CBC_SHA'),
        ('0032', 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA'),
        ('0033', 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA'),
        ('0034', 'TLS_DH_anon_WITH_AES_128_CBC_SHA'),
        ('0035', 'TLS_RSA_WITH_AES_256_CBC_SHA'),
        ('0036', 'TLS_DH_DSS_WITH_AES_256_CBC_SHA'),
        ('0037', 'TLS_DH_RSA_WITH_AES_256_CBC_SHA'),
        ('0038', 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA'),
        ('0039', 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA'),
        ('003A', 'TLS_DH_anon_WITH_AES_256_CBC_SHA'),
        ('003B', 'TLS_RSA_WITH_NULL_SHA256'),
        ('003C', 'TLS_RSA_WITH_AES_128_CBC_SHA256'),
        ('003D', 'TLS_RSA_WITH_AES_256_CBC_SHA256'),
        ('003E', 'TLS_DH_DSS_WITH_AES_128_CBC_SHA256'),
        ('003F', 'TLS_DH_RSA_WITH_AES_128_CBC_SHA256'),
        ('0040', 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA256'),
        ('0041', 'TLS_RSA_WITH_CAMELLIA_128_CBC_SHA'),
        ('0042', 'TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA'),
        ('0043', 'TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA'),
        ('0044', 'TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA'),
        ('0045', 'TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA'),
        ('0046', 'TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA'),
        # "0x00,0x47-4F","Reserved to avoid conflicts with deployed implementations",,, [Pasi_Eronen],
        # "0x00,0x50-58", Reserved to avoid conflicts,,,"[Pasi Eronen, <pasi.eronen&nokia.com>, 2008-04-04.  2008-04-04]",
        # "0x00,0x59-5C","Reserved to avoid conflicts with deployed implementations",,, [Pasi_Eronen],
        # "0x00,0x5D-5F", Unassigned,,,,
        # "0x00,0x60-66","Reserved to avoid conflicts with widely deployed implementations",,, [Pasi_Eronen],
        ('0067', 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256'),
        ('0068', 'TLS_DH_DSS_WITH_AES_256_CBC_SHA256'),
        ('0069', 'TLS_DH_RSA_WITH_AES_256_CBC_SHA256'),
        ('006A', 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA256'),
        ('006B', 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256'),
        ('006C', 'TLS_DH_anon_WITH_AES_128_CBC_SHA256'),
        ('006D', 'TLS_DH_anon_WITH_AES_256_CBC_SHA256'),
        # "0x00,0x6E-83", Unassigned,,,,
        ('0084', 'TLS_RSA_WITH_CAMELLIA_256_CBC_SHA'),
        ('0085', 'TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA'),
        ('0086', 'TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA'),
        ('0087', 'TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA'),
        ('0088', 'TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA'),
        ('0089', 'TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA'),
        ('008A', 'TLS_PSK_WITH_RC4_128_SHA'),
        ('008B', 'TLS_PSK_WITH_3DES_EDE_CBC_SHA'),
        ('008C', 'TLS_PSK_WITH_AES_128_CBC_SHA'),
        ('008D', 'TLS_PSK_WITH_AES_256_CBC_SHA'),
        ('008E', 'TLS_DHE_PSK_WITH_RC4_128_SHA'),
        ('008F', 'TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA'),
        ('0090', 'TLS_DHE_PSK_WITH_AES_128_CBC_SHA'),
        ('0091', 'TLS_DHE_PSK_WITH_AES_256_CBC_SHA'),
        ('0092', 'TLS_RSA_PSK_WITH_RC4_128_SHA'),
        ('0093', 'TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA'),
        ('0094', 'TLS_RSA_PSK_WITH_AES_128_CBC_SHA'),
        ('0095', 'TLS_RSA_PSK_WITH_AES_256_CBC_SHA'),
        ('0096', 'TLS_RSA_WITH_SEED_CBC_SHA'),
        ('0097', 'TLS_DH_DSS_WITH_SEED_CBC_SHA'),
        ('0098', 'TLS_DH_RSA_WITH_SEED_CBC_SHA'),
        ('0099', 'TLS_DHE_DSS_WITH_SEED_CBC_SHA'),
        ('009A', 'TLS_DHE_RSA_WITH_SEED_CBC_SHA'),
        ('009B', 'TLS_DH_anon_WITH_SEED_CBC_SHA'),
        ('009C', 'TLS_RSA_WITH_AES_128_GCM_SHA256'),
        ('009D', 'TLS_RSA_WITH_AES_256_GCM_SHA384'),
        ('009E', 'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256'),
        ('009F', 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384'),
        ('00A0', 'TLS_DH_RSA_WITH_AES_128_GCM_SHA256'),
        ('00A1', 'TLS_DH_RSA_WITH_AES_256_GCM_SHA384'),
        ('00A2', 'TLS_DHE_DSS_WITH_AES_128_GCM_SHA256'),
        ('00A3', 'TLS_DHE_DSS_WITH_AES_256_GCM_SHA384'),
        ('00A4', 'TLS_DH_DSS_WITH_AES_128_GCM_SHA256'),
        ('00A5', 'TLS_DH_DSS_WITH_AES_256_GCM_SHA384'),
        ('00A6', 'TLS_DH_anon_WITH_AES_128_GCM_SHA256'),
        ('00A7', 'TLS_DH_anon_WITH_AES_256_GCM_SHA384'),
        ('00A8', 'TLS_PSK_WITH_AES_128_GCM_SHA256'),
        ('00A9', 'TLS_PSK_WITH_AES_256_GCM_SHA384'),
        ('00AA', 'TLS_DHE_PSK_WITH_AES_128_GCM_SHA256'),
        ('00AB', 'TLS_DHE_PSK_WITH_AES_256_GCM_SHA384'),
        ('00AC', 'TLS_RSA_PSK_WITH_AES_128_GCM_SHA256'),
        ('00AD', 'TLS_RSA_PSK_WITH_AES_256_GCM_SHA384'),
        ('00AE', 'TLS_PSK_WITH_AES_128_CBC_SHA256'),
        ('00AF', 'TLS_PSK_WITH_AES_256_CBC_SHA384'),
        ('00B0', 'TLS_PSK_WITH_NULL_SHA256'),
        ('00B1', 'TLS_PSK_WITH_NULL_SHA384'),
        ('00B2', 'TLS_DHE_PSK_WITH_AES_128_CBC_SHA256'),
        ('00B3', 'TLS_DHE_PSK_WITH_AES_256_CBC_SHA384'),
        ('00B4', 'TLS_DHE_PSK_WITH_NULL_SHA256'),
        ('00B5', 'TLS_DHE_PSK_WITH_NULL_SHA384'),
        ('00B6', 'TLS_RSA_PSK_WITH_AES_128_CBC_SHA256'),
        ('00B7', 'TLS_RSA_PSK_WITH_AES_256_CBC_SHA384'),
        ('00B8', 'TLS_RSA_PSK_WITH_NULL_SHA256'),
        ('00B9', 'TLS_RSA_PSK_WITH_NULL_SHA384'),
        ('00BA', 'TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256'),
        ('00BB', 'TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256'),
        ('00BC', 'TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256'),
        ('00BD', 'TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256'),
        ('00BE', 'TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256'),
        ('00BF', 'TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256'),
        ('00C0', 'TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256'),
        ('00C1', 'TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256'),
        ('00C2', 'TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256'),
        ('00C3', 'TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256'),
        ('00C4', 'TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256'),
        ('00C5', 'TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256'),
        # "0x00,0xC6-FE", Unassigned,,,,
        ('00FF', 'TLS_EMPTY_RENEGOTIATION_INFO_SCSV'),
        # "0x01-12,*", Unassigned,,,,
        # "0x13,0x00", Unassigned,,,,
        ('1301', 'TLS_AES_128_GCM_SHA256'),
        ('1302', 'TLS_AES_256_GCM_SHA384'),
        ('1303', 'TLS_CHACHA20_POLY1305_SHA256'),
        ('1304', 'TLS_AES_128_CCM_SHA256'),
        ('1305', 'TLS_AES_128_CCM_8_SHA256'),
        # "0x13,0x06-0xFF", Unassigned,,,,
        # "0x14-55,*", Unassigned,,,,
        ('5600', 'TLS_FALLBACK_SCSV'),
        # "0x56,0x01-0xC0,0x00", Unassigned,,,,
        ('C001', 'TLS_ECDH_ECDSA_WITH_NULL_SHA'),
        ('C002', 'TLS_ECDH_ECDSA_WITH_RC4_128_SHA'),
        ('C003', 'TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA'),
        ('C004', 'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA'),
        ('C005', 'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA'),
        ('C006', 'TLS_ECDHE_ECDSA_WITH_NULL_SHA'),
        ('C007', 'TLS_ECDHE_ECDSA_WITH_RC4_128_SHA'),
        ('C008', 'TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA'),
        ('C009', 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA'),
        ('C00A', 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA'),
        ('C00B', 'TLS_ECDH_RSA_WITH_NULL_SHA'),
        ('C00C', 'TLS_ECDH_RSA_WITH_RC4_128_SHA'),
        ('C00D', 'TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA'),
        ('C00E', 'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA'),
        ('C00F', 'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA'),
        ('C010', 'TLS_ECDHE_RSA_WITH_NULL_SHA'),
        ('C011', 'TLS_ECDHE_RSA_WITH_RC4_128_SHA'),
        ('C012', 'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA'),
        ('C013', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA'),
        ('C014', 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA'),
        ('C015', 'TLS_ECDH_anon_WITH_NULL_SHA'),
        ('C016', 'TLS_ECDH_anon_WITH_RC4_128_SHA'),
        ('C017', 'TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA'),
        ('C018', 'TLS_ECDH_anon_WITH_AES_128_CBC_SHA'),
        ('C019', 'TLS_ECDH_anon_WITH_AES_256_CBC_SHA'),
        ('C01A', 'TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA'),
        ('C01B', 'TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA'),
        ('C01C', 'TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA'),
        ('C01D', 'TLS_SRP_SHA_WITH_AES_128_CBC_SHA'),
        ('C01E', 'TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA'),
        ('C01F', 'TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA'),
        ('C020', 'TLS_SRP_SHA_WITH_AES_256_CBC_SHA'),
        ('C021', 'TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA'),
        ('C022', 'TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA'),
        ('C023', 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256'),
        ('C024', 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384'),
        ('C025', 'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256'),
        ('C026', 'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384'),
        ('C027', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256'),
        ('C028', 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384'),
        ('C029', 'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256'),
        ('C02A', 'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384'),
        ('C02B', 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256'),
        ('C02C', 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384'),
        ('C02D', 'TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256'),
        ('C02E', 'TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384'),
        ('C02F', 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'),
        ('C030', 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384'),
        ('C031', 'TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256'),
        ('C032', 'TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384'),
        ('C033', 'TLS_ECDHE_PSK_WITH_RC4_128_SHA'),
        ('C034', 'TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA'),
        ('C035', 'TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA'),
        ('C036', 'TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA'),
        ('C037', 'TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256'),
        ('C038', 'TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384'),
        ('C039', 'TLS_ECDHE_PSK_WITH_NULL_SHA'),
        ('C03A', 'TLS_ECDHE_PSK_WITH_NULL_SHA256'),
        ('C03B', 'TLS_ECDHE_PSK_WITH_NULL_SHA384'),
        ('C03C', 'TLS_RSA_WITH_ARIA_128_CBC_SHA256'),
        ('C03D', 'TLS_RSA_WITH_ARIA_256_CBC_SHA384'),
        ('C03E', 'TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256'),
        ('C03F', 'TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384'),
        ('C040', 'TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256'),
        ('C041', 'TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384'),
        ('C042', 'TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256'),
        ('C043', 'TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384'),
        ('C044', 'TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256'),
        ('C045', 'TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384'),
        ('C046', 'TLS_DH_anon_WITH_ARIA_128_CBC_SHA256'),
        ('C047', 'TLS_DH_anon_WITH_ARIA_256_CBC_SHA384'),
        ('C048', 'TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256'),
        ('C049', 'TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384'),
        ('C04A', 'TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256'),
        ('C04B', 'TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384'),
        ('C04C', 'TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256'),
        ('C04D', 'TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384'),
        ('C04E', 'TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256'),
        ('C04F', 'TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384'),
        ('C050', 'TLS_RSA_WITH_ARIA_128_GCM_SHA256'),
        ('C051', 'TLS_RSA_WITH_ARIA_256_GCM_SHA384'),
        ('C052', 'TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256'),
        ('C053', 'TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384'),
        ('C054', 'TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256'),
        ('C055', 'TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384'),
        ('C056', 'TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256'),
        ('C057', 'TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384'),
        ('C058', 'TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256'),
        ('C059', 'TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384'),
        ('C05A', 'TLS_DH_anon_WITH_ARIA_128_GCM_SHA256'),
        ('C05B', 'TLS_DH_anon_WITH_ARIA_256_GCM_SHA384'),
        ('C05C', 'TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256'),
        ('C05D', 'TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384'),
        ('C05E', 'TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256'),
        ('C05F', 'TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384'),
        ('C060', 'TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256'),
        ('C061', 'TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384'),
        ('C062', 'TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256'),
        ('C063', 'TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384'),
        ('C064', 'TLS_PSK_WITH_ARIA_128_CBC_SHA256'),
        ('C065', 'TLS_PSK_WITH_ARIA_256_CBC_SHA384'),
        ('C066', 'TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256'),
        ('C067', 'TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384'),
        ('C068', 'TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256'),
        ('C069', 'TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384'),
        ('C06A', 'TLS_PSK_WITH_ARIA_128_GCM_SHA256'),
        ('C06B', 'TLS_PSK_WITH_ARIA_256_GCM_SHA384'),
        ('C06C', 'TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256'),
        ('C06D', 'TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384'),
        ('C06E', 'TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256'),
        ('C06F', 'TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384'),
        ('C070', 'TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256'),
        ('C071', 'TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384'),
        ('C072', 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256'),
        ('C073', 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384'),
        ('C074', 'TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256'),
        ('C075', 'TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384'),
        ('C076', 'TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256'),
        ('C077', 'TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384'),
        ('C078', 'TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256'),
        ('C079', 'TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384'),
        ('C07A', 'TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256'),
        ('C07B', 'TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384'),
        ('C07C', 'TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256'),
        ('C07D', 'TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384'),
        ('C07E', 'TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256'),
        ('C07F', 'TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384'),
        ('C080', 'TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256'),
        ('C081', 'TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384'),
        ('C082', 'TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256'),
        ('C083', 'TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384'),
        ('C084', 'TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256'),
        ('C085', 'TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384'),
        ('C086', 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256'),
        ('C087', 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384'),
        ('C088', 'TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256'),
        ('C089', 'TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384'),
        ('C08A', 'TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256'),
        ('C08B', 'TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384'),
        ('C08C', 'TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256'),
        ('C08D', 'TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384'),
        ('C08E', 'TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256'),
        ('C08F', 'TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384'),
        ('C090', 'TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256'),
        ('C091', 'TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384'),
        ('C092', 'TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256'),
        ('C093', 'TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384'),
        ('C094', 'TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256'),
        ('C095', 'TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384'),
        ('C096', 'TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256'),
        ('C097', 'TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384'),
        ('C098', 'TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256'),
        ('C099', 'TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384'),
        ('C09A', 'TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256'),
        ('C09B', 'TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384'),
        ('C09C', 'TLS_RSA_WITH_AES_128_CCM'),
        ('C09D', 'TLS_RSA_WITH_AES_256_CCM'),
        ('C09E', 'TLS_DHE_RSA_WITH_AES_128_CCM'),
        ('C09F', 'TLS_DHE_RSA_WITH_AES_256_CCM'),
        ('C0A0', 'TLS_RSA_WITH_AES_128_CCM_8'),
        ('C0A1', 'TLS_RSA_WITH_AES_256_CCM_8'),
        ('C0A2', 'TLS_DHE_RSA_WITH_AES_128_CCM_8'),
        ('C0A3', 'TLS_DHE_RSA_WITH_AES_256_CCM_8'),
        ('C0A4', 'TLS_PSK_WITH_AES_128_CCM'),
        ('C0A5', 'TLS_PSK_WITH_AES_256_CCM'),
        ('C0A6', 'TLS_DHE_PSK_WITH_AES_128_CCM'),
        ('C0A7', 'TLS_DHE_PSK_WITH_AES_256_CCM'),
        ('C0A8', 'TLS_PSK_WITH_AES_128_CCM_8'),
        ('C0A9', 'TLS_PSK_WITH_AES_256_CCM_8'),
        ('C0AA', 'TLS_PSK_DHE_WITH_AES_128_CCM_8'),
        ('C0AB', 'TLS_PSK_DHE_WITH_AES_256_CCM_8'),
        ('C0AC', 'TLS_ECDHE_ECDSA_WITH_AES_128_CCM'),
        ('C0AD', 'TLS_ECDHE_ECDSA_WITH_AES_256_CCM'),
        ('C0AE', 'TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8'),
        ('C0AF', 'TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8'),
        ('C0B0', 'TLS_ECCPWD_WITH_AES_128_GCM_SHA256'),
        ('C0B1', 'TLS_ECCPWD_WITH_AES_256_GCM_SHA384'),
        ('C0B2', 'TLS_ECCPWD_WITH_AES_128_CCM_SHA256'),
        ('C0B3', 'TLS_ECCPWD_WITH_AES_256_CCM_SHA384'),
        ('C0B4', 'TLS_SHA256_SHA256'),
        ('C0B5', 'TLS_SHA384_SHA384'),
        # "0xC0,0xB6-FF", Unassigned,,,,
        ('C100', 'TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC'),
        ('C101', 'TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC'),
        ('C102', 'TLS_GOSTR341112_256_WITH_28147_CNT_IMIT'),
        # "0xC1,0x03-FF", Unassigned,,,,
        # "0xC2-CB,*", Unassigned,,,,
        # "0xCC,0x00-A7", Unassigned,,,,
        ('CCA8', 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256'),
        ('CCA9', 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256'),
        ('CCAA', 'TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256'),
        ('CCAB', 'TLS_PSK_WITH_CHACHA20_POLY1305_SHA256'),
        ('CCAC', 'TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256'),
        ('CCAD', 'TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256'),
        ('CCAE', 'TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256'),
        # "0xCC,0xAF-FF", Unassigned,,,,
        # "0xCD-CF,*", Unassigned,,,,
        # "0xD0,0x00", Unassigned,,,,
        ('D001', 'TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256'),
        ('D002', 'TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384'),
        ('D003', 'TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256'),
        # "0xD0,0x04", Unassigned,,,,
        ('D005', 'TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256'),
        # "0xD0,0x06-FF", Unassigned,,,,
        # "0xD1-FD,*", Unassigned,,,,
        # "0xFE,0x00-FD", Unassigned,,,,
        # "0xFE,0xFE-FF","Reserved to avoid conflicts with widely deployed implementations",,, [Pasi_Eronen],
        # "0xFF,0x00-FF", Reserved for Private Use,,, [RFC8446],
    ]

    for cipher_suite in cipher_suites:
        (hex, description) = cipher_suite
        response = send_client_hello(host, port, '0302', hex)

        if (int(response[0]) == 22): # Check for Server Hello response. Else, assume error.
            print(description)

if __name__ == "__main__":
    main(sys.argv)