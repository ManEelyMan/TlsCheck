# TlsCheck
A tool to check the capabilities supported by a server's TLS channel.

I wrote this because a) I needed such a tool when doing pentests, and b) I wanted to learn more about the TLS protocol itself.

# Building:
Either open with Visual Studio and build it or run "dotnet build" from a VS command prompt.

# Usage
dotnet TlsCheck.dll <host> <port> [protocolversions|ciphersuites]

# Uses with example output:
D:\src>dotnet "D:\src\TlsCheck\src\c_sharp\bin\Debug\netcoreapp2.1\TlsCheck.dll" 10.0.0.1 443 protocolversions
Tls10
Tls11
Tls12
Tls13

D:\src>dotnet "D:\src\TlsCheck\src\c_sharp\bin\Debug\netcoreapp2.1\TlsCheck.dll" 10.0.0.1 443 ciphersuites
TLS_RSA_WITH_3DES_EDE_CBC_SHA
TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
TLS_RSA_WITH_AES_128_CBC_SHA
TLS_DHE_RSA_WITH_AES_128_CBC_SHA
TLS_RSA_WITH_AES_256_CBC_SHA
TLS_DHE_RSA_WITH_AES_256_CBC_SHA
TLS_RSA_WITH_AES_128_CBC_SHA256
TLS_RSA_WITH_AES_256_CBC_SHA256
TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
TLS_RSA_WITH_AES_128_GCM_SHA256
TLS_RSA_WITH_AES_256_GCM_SHA384
TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
