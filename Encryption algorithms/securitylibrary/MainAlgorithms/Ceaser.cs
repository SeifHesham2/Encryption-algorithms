using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            //throw new NotImplementedException();
            int e = 0;
            //changed all text to lower
            string txt_lwr = plainText.ToLower();
            //made an empty array to store new encrupted word
            string encr_txt = " ";

            for (int i = 0; i < txt_lwr.Length; i++)
            {
                int txt = (int)plainText[i];//casted text to be able to add the key
                e = (txt + key - 97) % 26 + 97; //we subtruct from 97 to map the ASCII code table of characters

                encr_txt += Char.ConvertFromUtf32(e);
            }

            //ToUpper to make the encrypted text (cipher text) in uppercase
            //Trim to git rid of the extra spaces
            encr_txt = encr_txt.ToUpper().Trim();
            return encr_txt;
        }

        public string Decrypt(string cipherText, int key)
        {
            //throw new NotImplementedException();
            int e = 0;
            string txt_upper = cipherText;
            //made an empty array to store new decrypted word
            string dec_txt = " ";

            for (int i = 0; i < txt_upper.Length; i++)
            {
                //casted text to be able to subtract from key
                int txt = (int)cipherText[i];
                int result = (txt - key - 65); //we subtruct from 65 to map the ASCII code table of characters

                // if the result equals negative number we have two cases
                if (result < 0)
                {
                    result *= -1;
                    e = (-1 * (result % 26)) + 65 + 26;
                }
                else
                    e = (txt - key - 65) % 26 + 65;

                dec_txt += Char.ConvertFromUtf32(e);
            }
            dec_txt = dec_txt.ToLower().Trim();
            return dec_txt;
        }
        public int Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            int key = 0;
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            int index_c = (int)cipherText[0] - 97;
            int index_p = (int)plainText[0] - 97;
            key = (index_c - index_p) % 26;
            if (key >= 0)
                return (key);
            else
                return (key + 26);
        }
    }
}