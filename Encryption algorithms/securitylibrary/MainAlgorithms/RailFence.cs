using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            int key = 0;
            for (int i = 2; i < plainText.Length - 1; i++)
            {
                string encryptedtext = Encrypt(plainText, i);
                StringBuilder ciphertextSB = new StringBuilder();
                for (int j = 0; j < encryptedtext.Length; j++)
                {
                    if ((encryptedtext[j] >= 'A') && (encryptedtext[j] <= 'Z'))
                    {
                        ciphertextSB.Append(encryptedtext[j]);
                    }

                }
                string ciphertext2 = ciphertextSB.ToString();
                if (cipherText == ciphertext2)
                {
                    key = i;
                    break;
                }
            }
            return key;
        }

        public string Decrypt(string cipherText, int key)
        {
            double columnNo = ((double)cipherText.Length / (double)key);
            int ceiledcolumnNo = (int)Math.Ceiling(columnNo);
            char[,] matrix = new char[key, cipherText.Length];
            int k = 0;
            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < ceiledcolumnNo; j++)
                {
                    if (k == cipherText.Length)
                    {
                        break;
                    }
                    matrix[i, j] = cipherText[k];
                    k = k + 1;
                }
            }
            StringBuilder PlaintextSB = new StringBuilder();
            for (int i = 0; i < ceiledcolumnNo; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    PlaintextSB.Append(matrix[j, i]);

                }
            }
            string Plaintext = PlaintextSB.ToString();
            Plaintext = Plaintext.ToUpper();

            return Plaintext;
        }

        public string Encrypt(string plainText, int key)
        {
            double columnNo = ((double)plainText.Length / (double)key);
            int ceiledcolumnNo = (int)Math.Ceiling(columnNo);
            char[,] matrix = new char[key, ceiledcolumnNo];
            int k = 0;
            for (int i = 0; i < ceiledcolumnNo; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    if (k == plainText.Length)
                    {
                        break;
                    }
                    matrix[j, i] = plainText[k];
                    k = k + 1;
                }
            }
            StringBuilder ciphertextSB = new StringBuilder();
            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < ceiledcolumnNo; j++)
                {
                    ciphertextSB.Append(matrix[i, j]);

                }
            }
            string ciphertext = ciphertextSB.ToString();
            ciphertext = ciphertext.ToUpper();
            return ciphertext;
        }
    }
}
