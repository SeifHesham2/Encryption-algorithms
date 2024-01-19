using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();

            string alphabets = "abcdefghijklmnopqrstuvwxyz";

            Dictionary<char, int> alpaMappings = new Dictionary<char, int>();
            Dictionary<int, char> rankingAlpha = new Dictionary<int, char>();

            for (int i = 0; i < alphabets.Length; i++)
            {
                alpaMappings[alphabets[i]] = i;
                rankingAlpha[i] = alphabets[i];
            }

            StringBuilder analysedKey = new StringBuilder();

            int index = 0;
            for (int i = 0; i < cipherText.Length; i++)
            {
                int counter = alpaMappings[plainText[i]];

                for (int j = 0; j < alphabets.Length; j++)
                {
                    if (alphabets[counter % 26] != cipherText[i])
                        counter++;
                    else
                    {
                        index = j;
                        break;
                    }
                }

                analysedKey.Append(rankingAlpha[index]);
            }

            int finalKeyIndex = 0;
            string allKey = analysedKey.ToString();
            string originalKey;
            originalKey = allKey.Substring(0, 3);

            for (int i = 3; i < allKey.Length; i++)
            {
                originalKey += allKey[i];
                int subStringIndex = allKey.IndexOf(originalKey, i);

                if (subStringIndex > i)
                {
                    if (finalKeyIndex == subStringIndex)
                        break;
                    else
                        finalKeyIndex = subStringIndex;
                }
            }

            return (allKey.Substring(0, finalKeyIndex));

        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            int size = (cipherText.Length - key.Length);

            string alphabets = "abcdefghijklmnopqrstuvwxyz";

            Dictionary<char, int> alpaMappings = new Dictionary<char, int>();
            Dictionary<int, char> rankingAlpha = new Dictionary<int, char>();


            for (int i = 0; i < alphabets.Length; i++)
            {
                alpaMappings[alphabets[i]] = i;
                rankingAlpha[i] = alphabets[i];
            }

            if (key.Length < cipherText.Length)
            {
                for (int i = 0; i < size; i++)
                    key += key[i];
            }

            Console.WriteLine(key);
            StringBuilder decryptedText = new StringBuilder();

            int index = 0;
            for (int i = 0; i < cipherText.Length; i++)
            {
                int counter = alpaMappings[key[i]];
                for (int j = 0; j < alphabets.Length; j++)
                {
                    if (alphabets[counter % 26] != cipherText[i])
                        counter++;
                    else
                    {
                        index = j;
                        break;
                    }
                }
                decryptedText.Append(rankingAlpha[index]);
            }

            return (decryptedText.ToString());
        }


        public string Encrypt(string plainText, string key)
        {

            plainText = plainText.ToLower();
            int size = (plainText.Length - key.Length);

            string alphabets = "abcdefghijklmnopqrstuvwxyz";

            Dictionary<char, int> alpaMappings = new Dictionary<char, int>();
            Dictionary<int, char> rankingAlpha = new Dictionary<int, char>();


            for (int i = 0; i < alphabets.Length; i++)
            {
                alpaMappings[alphabets[i]] = i;
                rankingAlpha[i] = alphabets[i];
            }

            if (key.Length < plainText.Length)
            {
                for (int i = 0; i < size; i++)
                {
                    key += key[i];
                }
            }

            StringBuilder encryptedText = new StringBuilder();
            int index = 0;
            for (int i = 0; i < plainText.Length; i++)
            {
                index = (alpaMappings[plainText[i]] + alpaMappings[key[i]]) % 26;
                encryptedText.Append(rankingAlpha[index]);
            }

            return encryptedText.ToString().ToUpper();
        }
    }
}