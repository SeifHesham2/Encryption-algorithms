using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {

            string alphabetsString = "abcdefghijklmnopqrstuvwxyz";
            Dictionary<char, char> encryptionDictionary = new Dictionary<char, char>(); //key =plain -> value=cipher
            Dictionary<char, int> keyDictionary = new Dictionary<char, int>();

            cipherText = cipherText.ToLower();

            for (int i = 0; i < plainText.Length; i++)
            {
                if (!encryptionDictionary.ContainsKey(plainText[i]))
                {
                    encryptionDictionary[plainText[i]] = cipherText[i];
                }
            }

            StringBuilder word = new StringBuilder();


            for (int i = 0; i < alphabetsString.Length; i++)
            {
                if (encryptionDictionary.ContainsKey(alphabetsString[i]))
                {
                    word.Append(encryptionDictionary[alphabetsString[i]]);
                    keyDictionary[encryptionDictionary[alphabetsString[i]]] = 1;
                }
                else
                {
                    word.Append(" ");
                }
            }

            for (int i = 0; i < word.Length - 1; i++)
            {
                if (word[i + 1] == ' ')
                {
                    char nextCharacter = (char)(word[i] + 1);

                    for (int j = 0; j < 26; j++)
                    {
                        if (nextCharacter == '{')
                            nextCharacter = 'a';
                        if (keyDictionary.ContainsKey(nextCharacter))
                        {

                            nextCharacter = (char)(nextCharacter + 1);
                        }
                        else
                        {
                            keyDictionary[nextCharacter] = 1;
                            word[i + 1] = nextCharacter;
                            break;
                        }
                    }
                }
            }
            return word.ToString();
        }

        public string Decrypt(string cipherText, string key)
        {
            string alphabetsString = "abcdefghijklmnopqrstuvwxyz";
            cipherText = cipherText.ToLower();

            Dictionary<char, char> encryptionDictionary = new Dictionary<char, char>();

            for (int i = 0; i < alphabetsString.Length; i++)
                encryptionDictionary[key[i]] = alphabetsString[i];


            StringBuilder word = new StringBuilder();

            foreach (char c in cipherText)
                word.Append(encryptionDictionary[c]);

            return word.ToString();
        }

        public string Encrypt(string plainText, string key)
        {
            string alphabetsString = "abcdefghijklmnopqrstuvwxyz";
            Dictionary<char, char> encryptionDictionary = new Dictionary<char, char>();

            for (int i = 0; i < alphabetsString.Length; i++)
                encryptionDictionary[alphabetsString[i]] = key[i];

            StringBuilder word = new StringBuilder();

            foreach (char c in plainText)
                word.Append(encryptionDictionary[c]);

            return word.ToString();
        }

        /// <summary>
        /// Frequency Information:
        /// 
        /// E   12.51%    h 5 //  etaoinsrhldcumfpgwybvkxjqz
        /// T	9.25      w
        /// A	8.04      d 1 
        /// O	7.60      r  15
        /// I	7.26      l 9
        /// N	7.09      q 14 
        /// S	6.54      v
        /// R	6.12      u
        /// H	5.49      o 8 
        /// L	4.14      k 12
        /// D	3.99      g 4
        /// C	3.06      f 3
        /// U	2.71      p
        /// M	2.53      s 13
        /// F	2.30      x 6
        /// P	2.00      i
        /// G	1.96      j 7 
        /// W	1.92      z
        /// Y	1.73      b
        /// B	1.54      e 2
        /// V	0.99      y
        /// K	0.67      n 11
        /// X	0.19      m
        /// J	0.16      a 10 
        /// Q	0.11      t 
        /// Z	0.09      c
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {

            Dictionary<char, int> alphabetInCipher = new Dictionary<char, int>();

            cipher = cipher.ToLower();
            for (int i = 0; i < cipher.Length; i++)
            {
                if (alphabetInCipher.ContainsKey(cipher[i]))
                    alphabetInCipher[cipher[i]]++;
                else
                    alphabetInCipher[cipher[i]] = 1;
            }

            var alphabetDict = from entry in alphabetInCipher orderby entry.Value descending select entry;

            string frequentLetters = "etaoinsrhldcumfpgwybvkxjqz";
            string alph = "abcdefghijklmnopqrstuvwxyz";


            Dictionary<char, char> formattedKey = new Dictionary<char, char>();
            StringBuilder newFrequentKey = new StringBuilder();

            foreach (var key in alphabetDict)
            {
                newFrequentKey.Append(key.Key);
            }

            for (int i = 0; i < 26; i++)
                formattedKey[frequentLetters[i]] = newFrequentKey[i];

            StringBuilder finalKey = new StringBuilder();

            for (int i = 0; i < 26; i++)
                finalKey.Append(formattedKey[alph[i]]);

            return Decrypt(cipher, finalKey.ToString());

        }
    }
}