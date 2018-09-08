using Newtonsoft.Json;
using System;
using System.IO;
using System.Security.Cryptography;

namespace WidevineDotnet
{
    public static class Util
    {
        internal static string Base64Encode(string plainText)
        {
            var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText);
            return Convert.ToBase64String(plainTextBytes);
        }


        internal static string Base64Decode(string base64EncodedData)
        {
            var base64EncodedBytes = Convert.FromBase64String(base64EncodedData);
            return System.Text.Encoding.UTF8.GetString(base64EncodedBytes);
        }


        internal static string ConvertToBase64(this Stream stream)
        {
            byte[] bytes;
            using (var memoryStream = new MemoryStream())
            {
                stream.CopyTo(memoryStream);
                bytes = memoryStream.ToArray();
            }

            string base64 = Convert.ToBase64String(bytes);
            return base64;
        }


        internal static byte[] EncryptAes(byte[] plain, byte[] Key, byte[] IV)
        {
            byte[] encrypted;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;
                aesAlg.Mode = CipherMode.CBC;

                var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
                using (var msEncrypt = new MemoryStream())
                {
                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        csEncrypt.Write(plain, 0, plain.Length);
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }
            return encrypted;
        }


        internal static byte[] HexStringToByteArray(string input)
        {
            var outputLength = input.Length / 2;
            var output = new byte[outputLength];
            using (var sr = new StringReader(input))
            {
                for (var i = 0; i < outputLength; i++)
                    output[i] = Convert.ToByte(new string(new char[2] { (char)sr.Read(), (char)sr.Read() }), 16);
            }
            return output;
        }

        internal static string JsonDump(object o)
        {
            //Equivalent to python json.dumps
            return JsonConvert.SerializeObject(o).Replace("\":", "\": ").Replace("\",", "\", ");
        }


        internal static byte[] PaddningBytes(byte[] hash)
        {
            byte[] paddning = { };
            if ((hash.Length % 16) != 0)
            {
                paddning = new byte[16 - (hash.Length % 16)];
            }
            byte[] hash_paddning = hash;
            if (paddning.Length > 0)
            {
                hash_paddning = new byte[hash.Length + paddning.Length];
                Buffer.BlockCopy(hash, 0, hash_paddning, 0, hash.Length);
                Buffer.BlockCopy(paddning, 0, hash_paddning, hash.Length, paddning.Length);
            }
            return hash_paddning;
        }
    }
}
