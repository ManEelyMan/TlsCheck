using System;
using System.Threading.Tasks;
using TlsCheck.Tls;

namespace TlsCheck
{
    class Program
    {
        static void Main(string[] args)
        {
            (string host, int port, Actions action) = ParseArguments(args);

            switch (action)
            {
                case Actions.ProtocolVersions:
                    TestHostForVersionSupportAsync(host, port).GetAwaiter().GetResult();
                    break;
                case Actions.CipherSuites:
                    TestHostForCipherSuiteCompatibilityAsync(host, port).GetAwaiter().GetResult();
                    break;
            }
        }

        private static (string, int, Actions) ParseArguments(string[] args)
        {
            try
            {
                if (args.Length < 3) throw new Exception("Invalid number of arguments.");

                string host = args[0];
                if (!ushort.TryParse(args[1], out ushort port)) throw new Exception($"Port argument isn't a valid int: {args[1]}");
                if (!Enum.TryParse<Actions>(args[2], true, out Actions action)) throw new Exception($"Invalid action argument: '{args[2]}'");

                return (host, port, action);
            }
            catch (Exception)
            {
                Console.WriteLine("Usage: dotnet.exe TlsCheck.dll <host> <port> [protocolversions|ciphersuites]");
                throw;
            }
        }

        private static async Task TestHostForVersionSupportAsync(string hostName, int port = 443)
        {
            foreach (var version in await Runner.GetSupportedProtocolVersionsAsync(hostName, port))
            {
                Console.WriteLine($"{version}");
            }
        }

        private static async Task TestHostForCipherSuiteCompatibilityAsync(string hostName, int port = 443, ProtocolVersion protocolVersion = ProtocolVersion.Tls12)
        {
            foreach (CipherSuites suite in await Runner.GetSupportedCipherSuitesAsync(hostName, port, protocolVersion))
            {
                Console.WriteLine($"{suite}");
            }
        }

        private enum Actions
            {
                ProtocolVersions,
                CipherSuites
            }
        }
}
