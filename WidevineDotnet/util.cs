using System;
using System.IO;
using System.Security.Cryptography;

namespace WidevineDotnet
{
    public static class Util
    {
        /// <summary>
        /// Encode a string to hexadecimal string
        /// </summary>
        /// <param name="plainText"></param>
        /// <returns></returns>
        internal static string Base64Encode(string plainText)
        {
            var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText);
            return Convert.ToBase64String(plainTextBytes);
        }

        /// <summary>
        /// Decode a hexadecimal string
        /// </summary>
        /// <param name="base64Encoded"></param>
        /// <returns></returns>
        internal static string Base64Decode(string base64Encoded)
        {
            var base64EncodedBytes = Convert.FromBase64String(base64Encoded);
            return System.Text.Encoding.UTF8.GetString(base64EncodedBytes);
        }

        /// <summary>
        /// Convert a stream to hexadecimal string
        /// </summary>
        /// <param name="stream"></param>
        /// <returns></returns>
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

        /// <summary>
        /// Encrypt a byte array with AES CBC
        /// </summary>
        /// <param name="hash_paddning"></param>
        /// <param name="Key"></param>
        /// <param name="IV"></param>
        /// <returns></returns>
        internal static byte[] EncryptAes(byte[] hash_paddning, byte[] Key, byte[] IV)
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
                        csEncrypt.Write(hash_paddning, 0, hash_paddning.Length);
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }
            return encrypted;
        }

        /// <summary>
        /// Convert a hexadecimal string to byte array
        /// </summary>
        /// <param name="base64Encoded"></param>
        /// <returns></returns>
        internal static byte[] HexStringToByteArray(string base64Encoded)
        {
            var outputLength = base64Encoded.Length / 2;
            var output = new byte[outputLength];
            using (var sr = new StringReader(base64Encoded))
            {
                for (var i = 0; i < outputLength; i++)
                    output[i] = Convert.ToByte(new string(new char[2] { (char)sr.Read(), (char)sr.Read() }), 16);
            }
            return output;
        }

        /// <summary>
        /// Bite padding a bite array to fill a 16-bite block
        /// </summary>
        /// <param name="hash"></param>
        /// <returns></returns>
        internal static byte[] PaddningBytes(byte[] hash)
        {
            if ((hash.Length % 16) == 0)
            {
                return hash;
            }
            else
            {
                byte[] paddning = new byte[16 - (hash.Length % 16)];
                byte[] hash_paddning = new byte[hash.Length + paddning.Length];
                Buffer.BlockCopy(hash, 0, hash_paddning, 0, hash.Length);
                Buffer.BlockCopy(paddning, 0, hash_paddning, hash.Length, paddning.Length);
                return hash_paddning;
            }
        }
    }
}