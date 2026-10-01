using System;
using System.IO;
using System.Text;

namespace Il2CppDumper
{
    public static class BinaryReaderExtensions
    {
        public static string ReadString(this BinaryReader reader, int numChars)
        {
            var start = reader.BaseStream.Position;
            
            var str = Encoding.UTF8.GetString(reader.ReadBytes(numChars * 4))[..numChars];
            
            reader.BaseStream.Position = start;
            reader.ReadBytes(Encoding.UTF8.GetByteCount(str));
            return str;
        }

        public static uint ReadULeb128(this BinaryReader reader)
        {
            uint value = reader.ReadByte();
            if (value >= 0x80)
            {
                var bitshift = 0;
                value &= 0x7f;
                while (true)
                {
                    var b = reader.ReadByte();
                    bitshift += 7;
                    value |= (uint)((b & 0x7f) << bitshift);
                    if (b < 0x80)
                        break;
                }
            }
            return value;
        }

        public static uint ReadCompressedUInt32(this BinaryReader reader)
        {
            uint val;
            var read = reader.ReadByte();

            if ((read & 0x80) == 0)
            {
                
                val = read;
            }
            else if ((read & 0xC0) == 0x80)
            {
                
                val = (read & ~0x80u) << 8;
                val |= reader.ReadByte();
            }
            else if ((read & 0xE0) == 0xC0)
            {
                
                val = (read & ~0xC0u) << 24;
                val |= ((uint)reader.ReadByte() << 16);
                val |= ((uint)reader.ReadByte() << 8);
                val |= reader.ReadByte();
            }
            else if (read == 0xF0)
            {
                
                val = reader.ReadUInt32();
            }
            else if (read == 0xFE)
            {
                
                val = uint.MaxValue - 1;
            }
            else if (read == 0xFF)
            {
                
                val = uint.MaxValue;
            }
            else
            {
                throw new Exception("Invalid compressed integer format");
            }

            return val;
        }

        public static int ReadCompressedInt32(this BinaryReader reader)
        {
            var encoded = reader.ReadCompressedUInt32();

            
            if (encoded == uint.MaxValue)
                return int.MinValue;

            bool isNegative = (encoded & 1) != 0;
            encoded >>= 1;
            if (isNegative)
                return -(int)(encoded + 1);
            return (int)encoded;
        }
    }
}
