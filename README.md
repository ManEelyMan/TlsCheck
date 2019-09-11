# TlsCheck
I created this because a) I needed such a tool when doing pentests, and b) I wanted to learn more about the TLS protocol itself.

These tools are a result of that.

My first attempt under /src/c_sharp was what I came up with while learning it. It could be considered a preliminary object library for TLS. It is written for dotnet core and thus can be used on any platform.

I took the learnings from my C# tool and created quick and dirty scripts in python and Powershell to do the same. (Python for my non-Microsoft friends :) )

All input/feedback is welcome. Hope someone else can enjoy this.

# /src/powershell

## Usage
TlsCheck.ps1 -TargetHost 10.0.0.1 -TargetPort 443

## Examples with output:
PS D:\src\TlsCheck\src\powershell> & D:\src\TlsCheck\src\powershell\TlsCheck.ps1 -TargetHost 10.0.0.1 -TargetPort 443
Testing TLS configuration of host 10.0.0.1, Port 443 ...

Supported Protocol Versions:
Tls10
Tls11
Tls12
Tls13

Supported Cipher Suites:
TLS_RSA_WITH_3DES_EDE_CBC_SHA
TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
TLS_RSA_WITH_AES_128_CBC_SHA
TLS_DHE_RSA_WITH_AES_128_CBC_SHA
TLS_RSA_WITH_AES_256_CBC_SHA
TLS_DHE_RSA_WITH_AES_256_CBC_SHA
TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA

# /src/python

## Usage
TlsCheck.py {host} {port}

## Examples with output:
d:\src\TlsCheck\src\python>.\TlsCheck.py 10.0.0.1 443
Testing TLS configuration of 10.0.0.1:443...

Supported versions of SSL/TLS:
Tls10
Tls11
Tls12
Tls13

Supported cipher suites:
TLS_RSA_WITH_3DES_EDE_CBC_SHA
TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
TLS_RSA_WITH_AES_128_CBC_SHA
TLS_DHE_RSA_WITH_AES_128_CBC_SHA
TLS_RSA_WITH_AES_256_CBC_SHA
TLS_DHE_RSA_WITH_AES_256_CBC_SHA
TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA

# /src/c_sharp

## Building:
Either open with Visual Studio and build it or run "dotnet build" from a VS command prompt.

## Usage
dotnet TlsCheck.dll {host} {port} [protocolversions|ciphersuites]

## Examples with output:
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
