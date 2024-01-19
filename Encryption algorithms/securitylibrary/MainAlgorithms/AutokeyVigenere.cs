using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
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
            string keystream = analysedKey.ToString();
            int counterr = 0;
            for (int j = 0; j < keystream.Length; j++)
            {
                if (plainText[0] != keystream[j])
                {
                    counterr++;
                }
                else
                {
                    break;
                }
            }
            string rightkey = keystream.Substring(0, counterr);
            return (rightkey);
        }

        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            cipherText = cipherText.ToUpper();
            key = key.ToUpper();
            int size = (cipherText.Length - key.Length);
            string alphabets = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            Dictionary<char, int> alpaMappings = new Dictionary<char, int>();
            Dictionary<int, char> rankingAlpha = new Dictionary<int, char>();

            for (int i = 0; i < alphabets.Length; i++)
            {
                alpaMappings[alphabets[i]] = i;
                rankingAlpha[i] = alphabets[i];
            }

            StringBuilder keyRemainder = new StringBuilder();
            int index = 0;
            if (key.Length < cipherText.Length)
            {
                for (int i = 0; i <= size; i++)
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
                    key += rankingAlpha[index];
                    keyRemainder.Append(rankingAlpha[index]);
                }
            }

            StringBuilder decryptedText = new StringBuilder();
            decryptedText = keyRemainder;
            index = 0;
            for (int i = size + 1; i < cipherText.Length; i++)
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
            return decryptedText.ToString();
        }

        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            //take the key and p.t and make the keystream
            string pt = plainText.ToUpper();
            string keyy = key.ToUpper();
            StringBuilder s = new StringBuilder(keyy);
            StringBuilder ct = new StringBuilder();
            string alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            if (pt.Length != keyy.Length)
            {
                int y = pt.Length - keyy.Length;
                for (int i = 0; i < y; i++)
                {
                    s.Append(pt[i]);
                }
            }
            string keycap = s.ToString();
            keycap = keycap.ToUpper();
            int x = 0;
            int z = 0;
            for (int i = 0; i < keycap.Length; i++)
            {
                for (int k = 0; k < alpha.Length; k++)
                {
                    if (pt[i] == alpha[k])
                    {
                        x = k;
                    }
                    if (keycap[i] == alpha[k])
                    {
                        z = k;
                    }

                }
                int yy = (x + z) % 26;
                ct.Append(alpha[yy]);

            }

            return ct.ToString();
        }
    }
}
