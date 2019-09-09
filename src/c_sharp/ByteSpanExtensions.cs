using System;
using System.Text;

namespace TlsCheck
{
    /// <summary>
    /// Extension methods to write certain objects to a Span<byte>.
    /// </summary>
    internal static class ByteSpanExtensions
    {
        public static volatile bool PrintBytesToConsole = false;

        public static ushort ReadUShort(this Span<byte> bytes, bool bigEndian = true)
        {
            if (bytes.Length < 2) throw new ArgumentOutOfRangeException(nameof(bytes));

            return ((ushort)(bigEndian ? ((bytes[0] << 8) | bytes[1]) : ((bytes[1] << 8) | bytes[0])));
        }

        public static uint WriteUShort(this Span<byte> bytes, ushort i, bool bigEndian = true)
        {
            if (bytes.Length < 2) throw new ArgumentOutOfRangeException(nameof(bytes));

            if (bigEndian)
            {
                //Big-Endian Write
                bytes[0] = (byte)((i >> 8) & 0xFF);
                bytes[1] = (byte)(i & 0xFF);
            }
            else
            {
                //Little-Endian Write
                bytes[0] = (byte)(i & 0xFF);
                bytes[1] = (byte)((i >> 8) & 0xFF);
            }

            return 2; // ushort = 2 bytes.
        }

        internal static uint WriteUInt(this Span<byte> bytes, uint i, bool bigEndian = true)
        {
            if (bytes.Length < 4) throw new ArgumentOutOfRangeException(nameof(bytes));

            if (bigEndian)
            {
                //Big-Endian Write
                bytes[0] = (byte)(i >> 24);
                bytes[1] = (byte)((i >> 16) & 0xFF);
                bytes[2] = (byte)((i >> 8) & 0xFF);
                bytes[3] = (byte)(i & 0xFF);
            }
            else
            {
                //Little-Endian Write
                bytes[0] = (byte)(i & 0xFF);
                bytes[1] = (byte)((i >> 8) & 0xFF);
                bytes[2] = (byte)((i >> 16) & 0xFF);
                bytes[3] = (byte)(i >> 24);
            }

            return 4;
        }

        internal static uint WriteBytes(this Span<byte> destination, Span<byte> source)
        {
            if (destination.Length < source.Length) throw new ArgumentOutOfRangeException(nameof(destination));

            source.CopyTo(destination);
            return (uint)source.Length;
        }

        internal static uint WriteString(this Span<byte> bytes, string str)
        {
            byte[] stringBytes = Encoding.ASCII.GetBytes(str);
            stringBytes.CopyTo(bytes);
            return (uint)stringBytes.Length;
        }

        internal static void PrintToConsole(this Span<byte> bytes, string description, uint numBytes)
        {
            if (!PrintBytesToConsole) return;

            Console.WriteLine($"{description} ({numBytes} bytes)");
            Console.WriteLine(Utilities.ConvertBytesToHexString(bytes, 0, (int)numBytes, lineLength: 16));
            Console.WriteLine();
        }

        internal static Span<byte> Slice(this Span<byte> bytes, uint index)
        {
            return bytes.Slice((int)index);
        }

        internal static Span<byte> Slice(this Span<byte> bytes, uint index, uint count)
        {
            return bytes.Slice((int)index, (int)count);
        }
    }
}
