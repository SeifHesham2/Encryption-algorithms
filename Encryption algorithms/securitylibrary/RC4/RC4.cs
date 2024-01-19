using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RC4
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class RC4 : CryptographicTechnique
    {
        static string HexConverter(string text)
        {
            text = text.Substring(2, text.Length - 2);

            byte[] bytes = new byte[text.Length / 2];
            string x = "";

            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(text.Substring(i * 2, 2), 16);
                x += char.ConvertFromUtf32(bytes[i]);
            }

            return x;
        }
        static string EncryptionDecryption(string text, string key)
        {
            bool hex = false; // If the input is hexadecimal
            if (text.Substring(0, 2) == "0x")
            {
                text = HexConverter(text);
                key = HexConverter(key);
                hex = true;
            }

            int[] S = new int[256];
            char[] T = new char[256];
            int keyLength = key.Length;

            for (int i = 0; i < S.Length; i++)
                S[i] = i;
            for (int i = 0; i < 256; i++)
                T[i] = key[i % keyLength];

            // Initial Permutation of S
            int j = 0;
            for (int i = 0; i < 255; i++)
            {
                j = (j + S[i] + T[i]) % 256;
                // Swap
                int temp = S[i];
                S[i] = S[j];
                S[j] = temp;
            }

            // Generation of Key stream K
            int m = j = 0;
            int textLength = text.Length;
            StringBuilder returnedText = new StringBuilder();
            int count = 0;

            while (count != textLength)
            {
                m = (m + 1) % 256;
                j = (j + S[m]) % 256;
                // Swap
                int temp = S[m];
                S[m] = S[j];
                S[j] = temp;

                int t = (S[m] + S[j]) % 256;

                int k = S[t];
                // Encryption/Decryption (XOR with K)
                returnedText.Append((char)(text[count] ^ k));

                count++;
            }

            if (hex)
            {
                byte[] bytes = Encoding.Default.GetBytes(returnedText.ToString());
                string hexString = BitConverter.ToString(bytes);

                hexString = hexString.Replace("-", "");
                hexString = "0x" + hexString.ToLower();

                return hexString;
            }
            else
                return returnedText.ToString();
        }

        public override string Decrypt(string cipherText, string key)
        {
            return EncryptionDecryption(cipherText, key);
        }

        public override  string Encrypt(string plainText, string key)
        {
            return EncryptionDecryption(plainText, key);
        }
    }
}
