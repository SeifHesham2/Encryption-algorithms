using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class TripleDES : ICryptographicTechnique<string, List<string>>
    {
        public string Decrypt(string cipherText, List<string> key)
        {
            //throw new NotImplementedException();
            string first = DES.EncryptionDecryption(cipherText, key[0], false);
            string second = DES.EncryptionDecryption(cipherText, key[1], true);
            string third = DES.EncryptionDecryption(cipherText, key[0], false);

            return third;
        }

        public string Encrypt(string plainText, List<string> key)
        {
            //throw new NotImplementedException();
            string first = DES.EncryptionDecryption(plainText, key[0], true);
            string second = DES.EncryptionDecryption(plainText, key[1], false);
            string third = DES.EncryptionDecryption(plainText, key[0], true);

            return third;
        }

        public List<string> Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

    }
}