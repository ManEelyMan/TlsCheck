param (
    [Parameter(Mandatory=$true)]
    [string]$TargetHost, 

    [Parameter(Mandatory=$true)]
    [int]$TargetPort
)

function Get-TlsInfo {

    param ([string]$TargetHost, [int]$TargetPort)

    Write-Host "Testing TLS configuration of host $TargetHost, Port $TargetPort ..."

    Write-Host ''
    Write-Host 'Supported Protocol Versions:'
    Test-SupportedProtocolVersions $TargetHost $TargetPort

    Write-Host ''
    Write-Host 'Supported Cipher Suites:'
    Test-SupportedCipherSuites $TargetHost $TargetPort
}

function Get-TlsResponse {

    param ([string]$TargetHost, [int]$TargetPort, [string]$protocolVersionHex, [string]$cipherSuiteHex)

    $unixEpochTime = [DateTimeOffset]::Now.ToUnixTimeSeconds()
    $unixEpochTimeHex = '{0:x8}' -f $unixEpochTime

    $cipherSuiteLengthInBytes = $cipherSuiteHex.Length / 2
    $cipherSuiteLengthHex = '{0:x4}' -f $cipherSuiteLengthInBytes

    $extensionsLength = 517 - (5 + 6 + 32 + 1 + 32 + 2 + 2 + 2 + $cipherSuiteLengthInBytes)  # Packet size minus all parts preceeding the extensions block.
    $extensionsLengthHex = '{0:x4}' -f $extensionsLength

    $paddingLength = $extensionsLength - 172 - 4 # Size of extensions - preceeding data and extension type and length bytes.
    $paddingLengthHex = '{0:x4}' -f $paddingLength

    $clientHelloHex = `
    '16' + $protocolVersionHex + '0200' +             # TLS Record Layer
    '010001fc' + $protocolVersionHex +                # Handshake Protocol: Client Hello
    $unixEpochTimeHex +                               # Unix Epoch Time (removing the '0x' from the front)
    (Get-RandomBytesInHex 28) +                       # 28 random bytes
    '20' +                                            # Session Id size
    (Get-RandomBytesInHex 32) +                       # 32 random bytes for the session id
    $cipherSuiteLengthHex +                           # Length of cipher suites
    $cipherSuiteHex +                                 # Cipher suites
    '0100' +                                          # Compression method (null)
    $extensionsLengthHex +                            # Extensions section length
    '7a7a000000170000ff01000100000a00' +              # Extensions (static list of typical ones)
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
    '0015' +                                          # Padding Extension
    $paddingLengthHex +                               # Padding Extension Length
    '0' * ($paddingLength*2)                          # Padding Data

    $request = Get-HexFromBytes $clientHelloHex

    [System.Net.Sockets.TcpClient] $tcpClient = [System.Net.Sockets.TcpClient]::new($TargetHost, $TargetPort)

    $tcpStream = $tcpClient.GetStream()
    $tcpStream.Write($request, 0, $request.Length)

    $response = New-Object byte[] 1024
    $tcpStream.ReadTimeout = 3000
    $tcpStream.Read($response, 0, $response.Length)
    $tcpClient.Close()

    $response
}

function Get-RandomBytesInHex {

    param([int]$numBytes)
    
    $buffer = New-Object byte[] $numBytes

    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($buffer)

    return ($buffer|ForEach-Object ToString X2) -join ''
}

function Get-HexFromBytes {
    
    param([string] $hex)

    $bytes = [byte[]]::new($hex.Length / 2)

    For($i=0; $i -lt $hex.Length; $i+=2){
        $bytes[$i/2] = [convert]::ToByte($hex.Substring($i, 2), 16)
    }

    $bytes    
}

function Test-SupportedProtocolVersions {

    param ([string]$TargetHost, [int]$TargetPort)

    $versions = @(
        [System.Tuple]::Create("0300", "Ssl30"),
        [System.Tuple]::Create("0301", "Tls10"),
        [System.Tuple]::Create("0302", "Tls11"),
        [System.Tuple]::Create("0303", "Tls12"),
        [System.Tuple]::Create("0304", "Tls13")
    )

    foreach ($version in $versions){
        $hex = $version.Item1
        $description = $version.Item2

        $response = Get-TlsResponse $TargetHost $TargetPort $hex '6a6a130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035000a'
        $firstByte = $response[1]

        if ($firstByte -eq 22) {
            Write-Host $description
        }
    }
}

function Test-SupportedCipherSuites {

    param ([string]$TargetHost, [int]$TargetPort)

    $cipher_suites = @(
        [System.Tuple]::Create('0000', 'TLS_NULL_WITH_NULL_NULL'),
        [System.Tuple]::Create('0001', 'TLS_RSA_WITH_NULL_MD5'),
        [System.Tuple]::Create('0002', 'TLS_RSA_WITH_NULL_SHA'),
        [System.Tuple]::Create('0003', 'TLS_RSA_EXPORT_WITH_RC4_40_MD5'),
        [System.Tuple]::Create('0004', 'TLS_RSA_WITH_RC4_128_MD5'),
        [System.Tuple]::Create('0005', 'TLS_RSA_WITH_RC4_128_SHA'),
        [System.Tuple]::Create('0006', 'TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5'),
        [System.Tuple]::Create('0007', 'TLS_RSA_WITH_IDEA_CBC_SHA'),
        [System.Tuple]::Create('0008', 'TLS_RSA_EXPORT_WITH_DES40_CBC_SHA'),
        [System.Tuple]::Create('0009', 'TLS_RSA_WITH_DES_CBC_SHA'),
        [System.Tuple]::Create('000A', 'TLS_RSA_WITH_3DES_EDE_CBC_SHA'),
        [System.Tuple]::Create('000B', 'TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA'),
        [System.Tuple]::Create('000C', 'TLS_DH_DSS_WITH_DES_CBC_SHA'),
        [System.Tuple]::Create('000D', 'TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA'),
        [System.Tuple]::Create('000E', 'TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA'),
        [System.Tuple]::Create('000F', 'TLS_DH_RSA_WITH_DES_CBC_SHA'),
        [System.Tuple]::Create('0010', 'TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA'),
        [System.Tuple]::Create('0011', 'TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA'),
        [System.Tuple]::Create('0012', 'TLS_DHE_DSS_WITH_DES_CBC_SHA'),
        [System.Tuple]::Create('0013', 'TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA'),
        [System.Tuple]::Create('0014', 'TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA'),
        [System.Tuple]::Create('0015', 'TLS_DHE_RSA_WITH_DES_CBC_SHA'),
        [System.Tuple]::Create('0016', 'TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA'),
        [System.Tuple]::Create('0017', 'TLS_DH_anon_EXPORT_WITH_RC4_40_MD5'),
        [System.Tuple]::Create('0018', 'TLS_DH_anon_WITH_RC4_128_MD5'),
        [System.Tuple]::Create('0019', 'TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA'),
        [System.Tuple]::Create('001A', 'TLS_DH_anon_WITH_DES_CBC_SHA'),
        [System.Tuple]::Create('001B', 'TLS_DH_anon_WITH_3DES_EDE_CBC_SHA'),
        # 0x001C, Reserved to avoid conflicts with SSLv3,,, [RFC5246],
        # 0x001D, Reserved to avoid conflicts with SSLv3,,, [RFC5246],
        [System.Tuple]::Create('001E', 'TLS_KRB5_WITH_DES_CBC_SHA'),
        [System.Tuple]::Create('001F', 'TLS_KRB5_WITH_3DES_EDE_CBC_SHA'),
        [System.Tuple]::Create('0020', 'TLS_KRB5_WITH_RC4_128_SHA'),
        [System.Tuple]::Create('0021', 'TLS_KRB5_WITH_IDEA_CBC_SHA'),
        [System.Tuple]::Create('0022', 'TLS_KRB5_WITH_DES_CBC_MD5'),
        [System.Tuple]::Create('0023', 'TLS_KRB5_WITH_3DES_EDE_CBC_MD5'),
        [System.Tuple]::Create('0024', 'TLS_KRB5_WITH_RC4_128_MD5'),
        [System.Tuple]::Create('0025', 'TLS_KRB5_WITH_IDEA_CBC_MD5'),
        [System.Tuple]::Create('0026', 'TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA'),
        [System.Tuple]::Create('0027', 'TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA'),
        [System.Tuple]::Create('0028', 'TLS_KRB5_EXPORT_WITH_RC4_40_SHA'),
        [System.Tuple]::Create('0029', 'TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5'),
        [System.Tuple]::Create('002A', 'TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5'),
        [System.Tuple]::Create('002B', 'TLS_KRB5_EXPORT_WITH_RC4_40_MD5'),
        [System.Tuple]::Create('002C', 'TLS_PSK_WITH_NULL_SHA'),
        [System.Tuple]::Create('002D', 'TLS_DHE_PSK_WITH_NULL_SHA'),
        [System.Tuple]::Create('002E', 'TLS_RSA_PSK_WITH_NULL_SHA'),
        [System.Tuple]::Create('002F', 'TLS_RSA_WITH_AES_128_CBC_SHA'),
        [System.Tuple]::Create('0030', 'TLS_DH_DSS_WITH_AES_128_CBC_SHA'),
        [System.Tuple]::Create('0031', 'TLS_DH_RSA_WITH_AES_128_CBC_SHA'),
        [System.Tuple]::Create('0032', 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA'),
        [System.Tuple]::Create('0033', 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA'),
        [System.Tuple]::Create('0034', 'TLS_DH_anon_WITH_AES_128_CBC_SHA'),
        [System.Tuple]::Create('0035', 'TLS_RSA_WITH_AES_256_CBC_SHA'),
        [System.Tuple]::Create('0036', 'TLS_DH_DSS_WITH_AES_256_CBC_SHA'),
        [System.Tuple]::Create('0037', 'TLS_DH_RSA_WITH_AES_256_CBC_SHA'),
        [System.Tuple]::Create('0038', 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA'),
        [System.Tuple]::Create('0039', 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA'),
        [System.Tuple]::Create('003A', 'TLS_DH_anon_WITH_AES_256_CBC_SHA'),
        [System.Tuple]::Create('003B', 'TLS_RSA_WITH_NULL_SHA256'),
        [System.Tuple]::Create('003C', 'TLS_RSA_WITH_AES_128_CBC_SHA256'),
        [System.Tuple]::Create('003D', 'TLS_RSA_WITH_AES_256_CBC_SHA256'),
        [System.Tuple]::Create('003E', 'TLS_DH_DSS_WITH_AES_128_CBC_SHA256'),
        [System.Tuple]::Create('003F', 'TLS_DH_RSA_WITH_AES_128_CBC_SHA256'),
        [System.Tuple]::Create('0040', 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA256'),
        [System.Tuple]::Create('0041', 'TLS_RSA_WITH_CAMELLIA_128_CBC_SHA'),
        [System.Tuple]::Create('0042', 'TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA'),
        [System.Tuple]::Create('0043', 'TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA'),
        [System.Tuple]::Create('0044', 'TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA'),
        [System.Tuple]::Create('0045', 'TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA'),
        [System.Tuple]::Create('0046', 'TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA'),
        # "0x00,0x47-4F","Reserved to avoid conflicts with deployed implementations",,, [Pasi_Eronen],
        # "0x00,0x50-58", Reserved to avoid conflicts,,,"[Pasi Eronen, <pasi.eronen&nokia.com>, 2008-04-04.  2008-04-04]",
        # "0x00,0x59-5C","Reserved to avoid conflicts with deployed implementations",,, [Pasi_Eronen],
        # "0x00,0x5D-5F", Unassigned,,,,
        # "0x00,0x60-66","Reserved to avoid conflicts with widely deployed implementations",,, [Pasi_Eronen],
        [System.Tuple]::Create('0067', 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256'),
        [System.Tuple]::Create('0068', 'TLS_DH_DSS_WITH_AES_256_CBC_SHA256'),
        [System.Tuple]::Create('0069', 'TLS_DH_RSA_WITH_AES_256_CBC_SHA256'),
        [System.Tuple]::Create('006A', 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA256'),
        [System.Tuple]::Create('006B', 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256'),
        [System.Tuple]::Create('006C', 'TLS_DH_anon_WITH_AES_128_CBC_SHA256'),
        [System.Tuple]::Create('006D', 'TLS_DH_anon_WITH_AES_256_CBC_SHA256'),
        # "0x00,0x6E-83", Unassigned,,,,
        [System.Tuple]::Create('0084', 'TLS_RSA_WITH_CAMELLIA_256_CBC_SHA'),
        [System.Tuple]::Create('0085', 'TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA'),
        [System.Tuple]::Create('0086', 'TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA'),
        [System.Tuple]::Create('0087', 'TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA'),
        [System.Tuple]::Create('0088', 'TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA'),
        [System.Tuple]::Create('0089', 'TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA'),
        [System.Tuple]::Create('008A', 'TLS_PSK_WITH_RC4_128_SHA'),
        [System.Tuple]::Create('008B', 'TLS_PSK_WITH_3DES_EDE_CBC_SHA'),
        [System.Tuple]::Create('008C', 'TLS_PSK_WITH_AES_128_CBC_SHA'),
        [System.Tuple]::Create('008D', 'TLS_PSK_WITH_AES_256_CBC_SHA'),
        [System.Tuple]::Create('008E', 'TLS_DHE_PSK_WITH_RC4_128_SHA'),
        [System.Tuple]::Create('008F', 'TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA'),
        [System.Tuple]::Create('0090', 'TLS_DHE_PSK_WITH_AES_128_CBC_SHA'),
        [System.Tuple]::Create('0091', 'TLS_DHE_PSK_WITH_AES_256_CBC_SHA'),
        [System.Tuple]::Create('0092', 'TLS_RSA_PSK_WITH_RC4_128_SHA'),
        [System.Tuple]::Create('0093', 'TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA'),
        [System.Tuple]::Create('0094', 'TLS_RSA_PSK_WITH_AES_128_CBC_SHA'),
        [System.Tuple]::Create('0095', 'TLS_RSA_PSK_WITH_AES_256_CBC_SHA'),
        [System.Tuple]::Create('0096', 'TLS_RSA_WITH_SEED_CBC_SHA'),
        [System.Tuple]::Create('0097', 'TLS_DH_DSS_WITH_SEED_CBC_SHA'),
        [System.Tuple]::Create('0098', 'TLS_DH_RSA_WITH_SEED_CBC_SHA'),
        [System.Tuple]::Create('0099', 'TLS_DHE_DSS_WITH_SEED_CBC_SHA'),
        [System.Tuple]::Create('009A', 'TLS_DHE_RSA_WITH_SEED_CBC_SHA'),
        [System.Tuple]::Create('009B', 'TLS_DH_anon_WITH_SEED_CBC_SHA'),
        [System.Tuple]::Create('009C', 'TLS_RSA_WITH_AES_128_GCM_SHA256'),
        [System.Tuple]::Create('009D', 'TLS_RSA_WITH_AES_256_GCM_SHA384'),
        [System.Tuple]::Create('009E', 'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256'),
        [System.Tuple]::Create('009F', 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384'),
        [System.Tuple]::Create('00A0', 'TLS_DH_RSA_WITH_AES_128_GCM_SHA256'),
        [System.Tuple]::Create('00A1', 'TLS_DH_RSA_WITH_AES_256_GCM_SHA384'),
        [System.Tuple]::Create('00A2', 'TLS_DHE_DSS_WITH_AES_128_GCM_SHA256'),
        [System.Tuple]::Create('00A3', 'TLS_DHE_DSS_WITH_AES_256_GCM_SHA384'),
        [System.Tuple]::Create('00A4', 'TLS_DH_DSS_WITH_AES_128_GCM_SHA256'),
        [System.Tuple]::Create('00A5', 'TLS_DH_DSS_WITH_AES_256_GCM_SHA384'),
        [System.Tuple]::Create('00A6', 'TLS_DH_anon_WITH_AES_128_GCM_SHA256'),
        [System.Tuple]::Create('00A7', 'TLS_DH_anon_WITH_AES_256_GCM_SHA384'),
        [System.Tuple]::Create('00A8', 'TLS_PSK_WITH_AES_128_GCM_SHA256'),
        [System.Tuple]::Create('00A9', 'TLS_PSK_WITH_AES_256_GCM_SHA384'),
        [System.Tuple]::Create('00AA', 'TLS_DHE_PSK_WITH_AES_128_GCM_SHA256'),
        [System.Tuple]::Create('00AB', 'TLS_DHE_PSK_WITH_AES_256_GCM_SHA384'),
        [System.Tuple]::Create('00AC', 'TLS_RSA_PSK_WITH_AES_128_GCM_SHA256'),
        [System.Tuple]::Create('00AD', 'TLS_RSA_PSK_WITH_AES_256_GCM_SHA384'),
        [System.Tuple]::Create('00AE', 'TLS_PSK_WITH_AES_128_CBC_SHA256'),
        [System.Tuple]::Create('00AF', 'TLS_PSK_WITH_AES_256_CBC_SHA384'),
        [System.Tuple]::Create('00B0', 'TLS_PSK_WITH_NULL_SHA256'),
        [System.Tuple]::Create('00B1', 'TLS_PSK_WITH_NULL_SHA384'),
        [System.Tuple]::Create('00B2', 'TLS_DHE_PSK_WITH_AES_128_CBC_SHA256'),
        [System.Tuple]::Create('00B3', 'TLS_DHE_PSK_WITH_AES_256_CBC_SHA384'),
        [System.Tuple]::Create('00B4', 'TLS_DHE_PSK_WITH_NULL_SHA256'),
        [System.Tuple]::Create('00B5', 'TLS_DHE_PSK_WITH_NULL_SHA384'),
        [System.Tuple]::Create('00B6', 'TLS_RSA_PSK_WITH_AES_128_CBC_SHA256'),
        [System.Tuple]::Create('00B7', 'TLS_RSA_PSK_WITH_AES_256_CBC_SHA384'),
        [System.Tuple]::Create('00B8', 'TLS_RSA_PSK_WITH_NULL_SHA256'),
        [System.Tuple]::Create('00B9', 'TLS_RSA_PSK_WITH_NULL_SHA384'),
        [System.Tuple]::Create('00BA', 'TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256'),
        [System.Tuple]::Create('00BB', 'TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256'),
        [System.Tuple]::Create('00BC', 'TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256'),
        [System.Tuple]::Create('00BD', 'TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256'),
        [System.Tuple]::Create('00BE', 'TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256'),
        [System.Tuple]::Create('00BF', 'TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256'),
        [System.Tuple]::Create('00C0', 'TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256'),
        [System.Tuple]::Create('00C1', 'TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256'),
        [System.Tuple]::Create('00C2', 'TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256'),
        [System.Tuple]::Create('00C3', 'TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256'),
        [System.Tuple]::Create('00C4', 'TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256'),
        [System.Tuple]::Create('00C5', 'TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256'),
        # "0x00,0xC6-FE", Unassigned,,,,
        [System.Tuple]::Create('00FF', 'TLS_EMPTY_RENEGOTIATION_INFO_SCSV'),
        # "0x01-12,*", Unassigned,,,,
        # "0x13,0x00", Unassigned,,,,
        [System.Tuple]::Create('1301', 'TLS_AES_128_GCM_SHA256'),
        [System.Tuple]::Create('1302', 'TLS_AES_256_GCM_SHA384'),
        [System.Tuple]::Create('1303', 'TLS_CHACHA20_POLY1305_SHA256'),
        [System.Tuple]::Create('1304', 'TLS_AES_128_CCM_SHA256'),
        [System.Tuple]::Create('1305', 'TLS_AES_128_CCM_8_SHA256'),
        # "0x13,0x06-0xFF", Unassigned,,,,
        # "0x14-55,*", Unassigned,,,,
        [System.Tuple]::Create('5600', 'TLS_FALLBACK_SCSV'),
        # "0x56,0x01-0xC0,0x00", Unassigned,,,,
        [System.Tuple]::Create('C001', 'TLS_ECDH_ECDSA_WITH_NULL_SHA'),
        [System.Tuple]::Create('C002', 'TLS_ECDH_ECDSA_WITH_RC4_128_SHA'),
        [System.Tuple]::Create('C003', 'TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA'),
        [System.Tuple]::Create('C004', 'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA'),
        [System.Tuple]::Create('C005', 'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA'),
        [System.Tuple]::Create('C006', 'TLS_ECDHE_ECDSA_WITH_NULL_SHA'),
        [System.Tuple]::Create('C007', 'TLS_ECDHE_ECDSA_WITH_RC4_128_SHA'),
        [System.Tuple]::Create('C008', 'TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA'),
        [System.Tuple]::Create('C009', 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA'),
        [System.Tuple]::Create('C00A', 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA'),
        [System.Tuple]::Create('C00B', 'TLS_ECDH_RSA_WITH_NULL_SHA'),
        [System.Tuple]::Create('C00C', 'TLS_ECDH_RSA_WITH_RC4_128_SHA'),
        [System.Tuple]::Create('C00D', 'TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA'),
        [System.Tuple]::Create('C00E', 'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA'),
        [System.Tuple]::Create('C00F', 'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA'),
        [System.Tuple]::Create('C010', 'TLS_ECDHE_RSA_WITH_NULL_SHA'),
        [System.Tuple]::Create('C011', 'TLS_ECDHE_RSA_WITH_RC4_128_SHA'),
        [System.Tuple]::Create('C012', 'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA'),
        [System.Tuple]::Create('C013', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA'),
        [System.Tuple]::Create('C014', 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA'),
        [System.Tuple]::Create('C015', 'TLS_ECDH_anon_WITH_NULL_SHA'),
        [System.Tuple]::Create('C016', 'TLS_ECDH_anon_WITH_RC4_128_SHA'),
        [System.Tuple]::Create('C017', 'TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA'),
        [System.Tuple]::Create('C018', 'TLS_ECDH_anon_WITH_AES_128_CBC_SHA'),
        [System.Tuple]::Create('C019', 'TLS_ECDH_anon_WITH_AES_256_CBC_SHA'),
        [System.Tuple]::Create('C01A', 'TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA'),
        [System.Tuple]::Create('C01B', 'TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA'),
        [System.Tuple]::Create('C01C', 'TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA'),
        [System.Tuple]::Create('C01D', 'TLS_SRP_SHA_WITH_AES_128_CBC_SHA'),
        [System.Tuple]::Create('C01E', 'TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA'),
        [System.Tuple]::Create('C01F', 'TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA'),
        [System.Tuple]::Create('C020', 'TLS_SRP_SHA_WITH_AES_256_CBC_SHA'),
        [System.Tuple]::Create('C021', 'TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA'),
        [System.Tuple]::Create('C022', 'TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA'),
        [System.Tuple]::Create('C023', 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256'),
        [System.Tuple]::Create('C024', 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384'),
        [System.Tuple]::Create('C025', 'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256'),
        [System.Tuple]::Create('C026', 'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384'),
        [System.Tuple]::Create('C027', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256'),
        [System.Tuple]::Create('C028', 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384'),
        [System.Tuple]::Create('C029', 'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256'),
        [System.Tuple]::Create('C02A', 'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384'),
        [System.Tuple]::Create('C02B', 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256'),
        [System.Tuple]::Create('C02C', 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384'),
        [System.Tuple]::Create('C02D', 'TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256'),
        [System.Tuple]::Create('C02E', 'TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384'),
        [System.Tuple]::Create('C02F', 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'),
        [System.Tuple]::Create('C030', 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384'),
        [System.Tuple]::Create('C031', 'TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256'),
        [System.Tuple]::Create('C032', 'TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384'),
        [System.Tuple]::Create('C033', 'TLS_ECDHE_PSK_WITH_RC4_128_SHA'),
        [System.Tuple]::Create('C034', 'TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA'),
        [System.Tuple]::Create('C035', 'TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA'),
        [System.Tuple]::Create('C036', 'TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA'),
        [System.Tuple]::Create('C037', 'TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256'),
        [System.Tuple]::Create('C038', 'TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384'),
        [System.Tuple]::Create('C039', 'TLS_ECDHE_PSK_WITH_NULL_SHA'),
        [System.Tuple]::Create('C03A', 'TLS_ECDHE_PSK_WITH_NULL_SHA256'),
        [System.Tuple]::Create('C03B', 'TLS_ECDHE_PSK_WITH_NULL_SHA384'),
        [System.Tuple]::Create('C03C', 'TLS_RSA_WITH_ARIA_128_CBC_SHA256'),
        [System.Tuple]::Create('C03D', 'TLS_RSA_WITH_ARIA_256_CBC_SHA384'),
        [System.Tuple]::Create('C03E', 'TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256'),
        [System.Tuple]::Create('C03F', 'TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384'),
        [System.Tuple]::Create('C040', 'TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256'),
        [System.Tuple]::Create('C041', 'TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384'),
        [System.Tuple]::Create('C042', 'TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256'),
        [System.Tuple]::Create('C043', 'TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384'),
        [System.Tuple]::Create('C044', 'TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256'),
        [System.Tuple]::Create('C045', 'TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384'),
        [System.Tuple]::Create('C046', 'TLS_DH_anon_WITH_ARIA_128_CBC_SHA256'),
        [System.Tuple]::Create('C047', 'TLS_DH_anon_WITH_ARIA_256_CBC_SHA384'),
        [System.Tuple]::Create('C048', 'TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256'),
        [System.Tuple]::Create('C049', 'TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384'),
        [System.Tuple]::Create('C04A', 'TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256'),
        [System.Tuple]::Create('C04B', 'TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384'),
        [System.Tuple]::Create('C04C', 'TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256'),
        [System.Tuple]::Create('C04D', 'TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384'),
        [System.Tuple]::Create('C04E', 'TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256'),
        [System.Tuple]::Create('C04F', 'TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384'),
        [System.Tuple]::Create('C050', 'TLS_RSA_WITH_ARIA_128_GCM_SHA256'),
        [System.Tuple]::Create('C051', 'TLS_RSA_WITH_ARIA_256_GCM_SHA384'),
        [System.Tuple]::Create('C052', 'TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256'),
        [System.Tuple]::Create('C053', 'TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384'),
        [System.Tuple]::Create('C054', 'TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256'),
        [System.Tuple]::Create('C055', 'TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384'),
        [System.Tuple]::Create('C056', 'TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256'),
        [System.Tuple]::Create('C057', 'TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384'),
        [System.Tuple]::Create('C058', 'TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256'),
        [System.Tuple]::Create('C059', 'TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384'),
        [System.Tuple]::Create('C05A', 'TLS_DH_anon_WITH_ARIA_128_GCM_SHA256'),
        [System.Tuple]::Create('C05B', 'TLS_DH_anon_WITH_ARIA_256_GCM_SHA384'),
        [System.Tuple]::Create('C05C', 'TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256'),
        [System.Tuple]::Create('C05D', 'TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384'),
        [System.Tuple]::Create('C05E', 'TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256'),
        [System.Tuple]::Create('C05F', 'TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384'),
        [System.Tuple]::Create('C060', 'TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256'),
        [System.Tuple]::Create('C061', 'TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384'),
        [System.Tuple]::Create('C062', 'TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256'),
        [System.Tuple]::Create('C063', 'TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384'),
        [System.Tuple]::Create('C064', 'TLS_PSK_WITH_ARIA_128_CBC_SHA256'),
        [System.Tuple]::Create('C065', 'TLS_PSK_WITH_ARIA_256_CBC_SHA384'),
        [System.Tuple]::Create('C066', 'TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256'),
        [System.Tuple]::Create('C067', 'TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384'),
        [System.Tuple]::Create('C068', 'TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256'),
        [System.Tuple]::Create('C069', 'TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384'),
        [System.Tuple]::Create('C06A', 'TLS_PSK_WITH_ARIA_128_GCM_SHA256'),
        [System.Tuple]::Create('C06B', 'TLS_PSK_WITH_ARIA_256_GCM_SHA384'),
        [System.Tuple]::Create('C06C', 'TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256'),
        [System.Tuple]::Create('C06D', 'TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384'),
        [System.Tuple]::Create('C06E', 'TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256'),
        [System.Tuple]::Create('C06F', 'TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384'),
        [System.Tuple]::Create('C070', 'TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256'),
        [System.Tuple]::Create('C071', 'TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384'),
        [System.Tuple]::Create('C072', 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256'),
        [System.Tuple]::Create('C073', 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384'),
        [System.Tuple]::Create('C074', 'TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256'),
        [System.Tuple]::Create('C075', 'TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384'),
        [System.Tuple]::Create('C076', 'TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256'),
        [System.Tuple]::Create('C077', 'TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384'),
        [System.Tuple]::Create('C078', 'TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256'),
        [System.Tuple]::Create('C079', 'TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384'),
        [System.Tuple]::Create('C07A', 'TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256'),
        [System.Tuple]::Create('C07B', 'TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384'),
        [System.Tuple]::Create('C07C', 'TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256'),
        [System.Tuple]::Create('C07D', 'TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384'),
        [System.Tuple]::Create('C07E', 'TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256'),
        [System.Tuple]::Create('C07F', 'TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384'),
        [System.Tuple]::Create('C080', 'TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256'),
        [System.Tuple]::Create('C081', 'TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384'),
        [System.Tuple]::Create('C082', 'TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256'),
        [System.Tuple]::Create('C083', 'TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384'),
        [System.Tuple]::Create('C084', 'TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256'),
        [System.Tuple]::Create('C085', 'TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384'),
        [System.Tuple]::Create('C086', 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256'),
        [System.Tuple]::Create('C087', 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384'),
        [System.Tuple]::Create('C088', 'TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256'),
        [System.Tuple]::Create('C089', 'TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384'),
        [System.Tuple]::Create('C08A', 'TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256'),
        [System.Tuple]::Create('C08B', 'TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384'),
        [System.Tuple]::Create('C08C', 'TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256'),
        [System.Tuple]::Create('C08D', 'TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384'),
        [System.Tuple]::Create('C08E', 'TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256'),
        [System.Tuple]::Create('C08F', 'TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384'),
        [System.Tuple]::Create('C090', 'TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256'),
        [System.Tuple]::Create('C091', 'TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384'),
        [System.Tuple]::Create('C092', 'TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256'),
        [System.Tuple]::Create('C093', 'TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384'),
        [System.Tuple]::Create('C094', 'TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256'),
        [System.Tuple]::Create('C095', 'TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384'),
        [System.Tuple]::Create('C096', 'TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256'),
        [System.Tuple]::Create('C097', 'TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384'),
        [System.Tuple]::Create('C098', 'TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256'),
        [System.Tuple]::Create('C099', 'TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384'),
        [System.Tuple]::Create('C09A', 'TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256'),
        [System.Tuple]::Create('C09B', 'TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384'),
        [System.Tuple]::Create('C09C', 'TLS_RSA_WITH_AES_128_CCM'),
        [System.Tuple]::Create('C09D', 'TLS_RSA_WITH_AES_256_CCM'),
        [System.Tuple]::Create('C09E', 'TLS_DHE_RSA_WITH_AES_128_CCM'),
        [System.Tuple]::Create('C09F', 'TLS_DHE_RSA_WITH_AES_256_CCM'),
        [System.Tuple]::Create('C0A0', 'TLS_RSA_WITH_AES_128_CCM_8'),
        [System.Tuple]::Create('C0A1', 'TLS_RSA_WITH_AES_256_CCM_8'),
        [System.Tuple]::Create('C0A2', 'TLS_DHE_RSA_WITH_AES_128_CCM_8'),
        [System.Tuple]::Create('C0A3', 'TLS_DHE_RSA_WITH_AES_256_CCM_8'),
        [System.Tuple]::Create('C0A4', 'TLS_PSK_WITH_AES_128_CCM'),
        [System.Tuple]::Create('C0A5', 'TLS_PSK_WITH_AES_256_CCM'),
        [System.Tuple]::Create('C0A6', 'TLS_DHE_PSK_WITH_AES_128_CCM'),
        [System.Tuple]::Create('C0A7', 'TLS_DHE_PSK_WITH_AES_256_CCM'),
        [System.Tuple]::Create('C0A8', 'TLS_PSK_WITH_AES_128_CCM_8'),
        [System.Tuple]::Create('C0A9', 'TLS_PSK_WITH_AES_256_CCM_8'),
        [System.Tuple]::Create('C0AA', 'TLS_PSK_DHE_WITH_AES_128_CCM_8'),
        [System.Tuple]::Create('C0AB', 'TLS_PSK_DHE_WITH_AES_256_CCM_8'),
        [System.Tuple]::Create('C0AC', 'TLS_ECDHE_ECDSA_WITH_AES_128_CCM'),
        [System.Tuple]::Create('C0AD', 'TLS_ECDHE_ECDSA_WITH_AES_256_CCM'),
        [System.Tuple]::Create('C0AE', 'TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8'),
        [System.Tuple]::Create('C0AF', 'TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8'),
        [System.Tuple]::Create('C0B0', 'TLS_ECCPWD_WITH_AES_128_GCM_SHA256'),
        [System.Tuple]::Create('C0B1', 'TLS_ECCPWD_WITH_AES_256_GCM_SHA384'),
        [System.Tuple]::Create('C0B2', 'TLS_ECCPWD_WITH_AES_128_CCM_SHA256'),
        [System.Tuple]::Create('C0B3', 'TLS_ECCPWD_WITH_AES_256_CCM_SHA384'),
        [System.Tuple]::Create('C0B4', 'TLS_SHA256_SHA256'),
        [System.Tuple]::Create('C0B5', 'TLS_SHA384_SHA384'),
        # "0xC0,0xB6-FF", Unassigned,,,,
        [System.Tuple]::Create('C100', 'TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC'),
        [System.Tuple]::Create('C101', 'TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC'),
        [System.Tuple]::Create('C102', 'TLS_GOSTR341112_256_WITH_28147_CNT_IMIT'),
        # "0xC1,0x03-FF", Unassigned,,,,
        # "0xC2-CB,*", Unassigned,,,,
        # "0xCC,0x00-A7", Unassigned,,,,
        [System.Tuple]::Create('CCA8', 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256'),
        [System.Tuple]::Create('CCA9', 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256'),
        [System.Tuple]::Create('CCAA', 'TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256'),
        [System.Tuple]::Create('CCAB', 'TLS_PSK_WITH_CHACHA20_POLY1305_SHA256'),
        [System.Tuple]::Create('CCAC', 'TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256'),
        [System.Tuple]::Create('CCAD', 'TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256'),
        [System.Tuple]::Create('CCAE', 'TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256'),
        # "0xCC,0xAF-FF", Unassigned,,,,
        # "0xCD-CF,*", Unassigned,,,,
        # "0xD0,0x00", Unassigned,,,,
        [System.Tuple]::Create('D001', 'TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256'),
        [System.Tuple]::Create('D002', 'TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384'),
        [System.Tuple]::Create('D003', 'TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256'),
        # "0xD0,0x04", Unassigned,,,,
        [System.Tuple]::Create('D005', 'TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256')
        # "0xD0,0x06-FF", Unassigned,,,,
        # "0xD1-FD,*", Unassigned,,,,
        # "0xFE,0x00-FD", Unassigned,,,,
        # "0xFE,0xFE-FF","Reserved to avoid conflicts with widely deployed implementations",,, [Pasi_Eronen],
        # "0xFF,0x00-FF", Reserved for Private Use,,, [RFC8446],
    )

    foreach ($cipher_suite in $cipher_suites){
        $hex = $cipher_suite.Item1
        $description = $cipher_suite.Item2

        $response = Get-TlsResponse $TargetHost $TargetPort '0302' $hex
        $firstByte = $response[1]

        if ($firstByte -eq 22) {
            Write-Host $description
        }
    }
}

Get-TlsInfo $TargetHost $TargetPort

