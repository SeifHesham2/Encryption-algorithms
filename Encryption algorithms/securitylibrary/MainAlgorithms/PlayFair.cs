using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        public string Decrypt(string cipherText, string key)
        {

            string key2 = key.ToUpper();
            string unique = string.Empty;
            var set = new HashSet<char>(key2);
            foreach (char c in set)
            {
                unique += c;
            }
            int counterformatrix = 0;
            string alpha = "ABCDEFGHIKLMNOPQRSTUVWXYZ";
            StringBuilder sb = new StringBuilder(alpha);
            //Remove charachters of key from alpha
            for (int i = 0; i < unique.Length; i++)
            {
                for (int j = 0; j < 24; j++)
                {
                    if (unique[i] == alpha[j])
                    {

                        sb[j] = ' ';

                    }
                }


            }
            StringBuilder sb2 = new StringBuilder();
            for (int i = 0; i < sb.Length; i++)
            {
                if (sb[i] == ' ')
                {
                    continue;
                }
                else
                {
                    sb2.Append(sb[i]);
                }

            }

            string remalpha = sb2.ToString();
            //Fill the matrix with the key and the remaining letters of alphabet
            string matrixchars = unique + remalpha;
            char[,] matrix = new char[5, 5];
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {

                    matrix[i, j] = matrixchars[counterformatrix];
                    counterformatrix++;
                }

            }
            //print the matrix
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    Console.Write("{0}\t", matrix[i, j]);
                }
                Console.Write(Environment.NewLine + Environment.NewLine);
            }



            // split every to chars

            string finaltext = cipherText.ToUpper();
            var twochar = new List<string>();
            for (int i = 0; i < finaltext.Length; i += 2)
                twochar.Add(finaltext.Substring(i, 2));
            StringBuilder plaintextstring = new StringBuilder();
            int i1 = -1, j1 = -1, i2 = -1, j2 = -1;
            for (int n = 0; n < twochar.Count(); n++)
            {
                string doublechar = twochar[n];
                ///STORE I AND J ////
                for (int k = 0; k < 2; k++)
                {
                    for (int i = 0; i < 5; i++)
                    {

                        for (int j = 0; j < 5; j++)
                        {
                            if (k == 0)
                            {
                                if (matrix[i, j] == doublechar[k])
                                {
                                    i1 = i;
                                    j1 = j;
                                }
                            }
                            else
                            {
                                if (matrix[i, j] == doublechar[k])
                                {
                                    i2 = i;
                                    j2 = j;
                                }

                            }
                        }


                    }

                }
                ///////////////////////////////////// decryption ALGO ////////////////////////////////////////////
                if (i1 == i2)
                {
                    if (j1 == 0)
                    {
                        j1 = 5;
                    }
                    if (j2 == 0)
                    {
                        j2 = 5;
                    }
                    j1 = ((j1 - 1) % (5));
                    j2 = ((j2 - 1) % (5));
                    plaintextstring.Append(matrix[i1, j1]);
                    plaintextstring.Append(matrix[i2, j2]);
                }
                else if (j2 == j1)
                {

                    if (i1 == 0)
                    {
                        i1 = 5;
                    }
                    if (i2 == 0)
                    {
                        i2 = 5;
                    }
                    i1 = ((i1 - 1) % (5));
                    i2 = ((i2 - 1) % (5));
                    plaintextstring.Append(matrix[i1, j1]);
                    plaintextstring.Append(matrix[i2, j2]);
                }
                else
                {
                    plaintextstring.Append(matrix[i1, j2]);
                    plaintextstring.Append(matrix[i2, j1]);
                }
                i1 = 0;
                j1 = 0;
                i2 = 0;
                j2 = 0;
            }
            // remove last x from string //
            if (plaintextstring[plaintextstring.Length - 1] == 'X')
            {
                plaintextstring.Remove(plaintextstring.Length - 1, 1);
            }
            /////////////////// remove the x between 2 char /////////////////////
            string plaintextwithX = plaintextstring.ToString();
            StringBuilder removexstringB = new StringBuilder(plaintextwithX);
            for (int i = 1; i < removexstringB.Length; i = i + 2)
            {
                if (removexstringB[i] == 'X' && removexstringB[i + 1] == removexstringB[i - 1])
                {
                    removexstringB.Remove(i, 1);
                    i = i + 1;

                }
            }
            ///////////////return string ///////////////
            string plaintext = removexstringB.ToString();
            return plaintext;
        }



        public string Encrypt(string plainText, string key)
        {
            //Remove duplicates from the keyword


            string key2 = key.ToUpper();
            string unique = string.Empty;
            var set = new HashSet<char>(key2);
            foreach (char c in set)
            {
                unique += c;
            }
            int counterformatrix = 0;
            string alpha = "ABCDEFGHIKLMNOPQRSTUVWXYZ";
            StringBuilder sb = new StringBuilder(alpha);
            //Remove charachters of key from alpha
            for (int i = 0; i < unique.Length; i++)
            {
                for (int j = 0; j < 24; j++)
                {
                    if (unique[i] == alpha[j])
                    {

                        sb[j] = ' ';

                    }
                }


            }
            StringBuilder sb2 = new StringBuilder();
            for (int i = 0; i < sb.Length; i++)
            {
                if (sb[i] == ' ')
                {
                    continue;
                }
                else
                {
                    sb2.Append(sb[i]);
                }

            }

            string remalpha = sb2.ToString();
            //Fill the matrix with the key and the remaining letters of alphabet
            string matrixchars = unique + remalpha;
            char[,] matrix = new char[5, 5];
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {

                    matrix[i, j] = matrixchars[counterformatrix];
                    counterformatrix++;
                }

            }
            //print the matrix
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    Console.Write("{0}\t", matrix[i, j]);
                }
                Console.Write(Environment.NewLine + Environment.NewLine);
            }

            //Handle the plaintext 
            //remove spaces
            StringBuilder sb3 = new StringBuilder();
            for (int i = 0; i < plainText.Length; i++)
            {
                if (plainText[i] == ' ')
                {
                    continue;
                }
                else
                {
                    sb3.Append(plainText[i]);
                }
            }
            //uppercase
            string text2 = sb3.ToString();
            string uppertext = text2.ToUpper();
            //insert x between 2 char;
            int length = uppertext.Length;
            for (int i = 0; i < length - 1; i += 2)
            {

                if (uppertext[i] == uppertext[i + 1])
                {
                    uppertext = uppertext.Insert(i + 1, "X");
                    length++;
                }


            }
            //insert x at the last of string
            StringBuilder sb4 = new StringBuilder(uppertext);

            if (sb4.Length % 2 != 0)
            {
                sb4.Append('X');


            }
            // final text
            string finaltext = sb4.ToString();
            // split every to chars
            var twochar = new List<string>();
            for (int i = 0; i < finaltext.Length; i += 2)
                twochar.Add(finaltext.Substring(i, 2));

            ///////encryption////////////
            StringBuilder encryptionstring = new StringBuilder();
            int i1 = -1, j1 = -1, i2 = -1, j2 = -1;
            for (int n = 0; n < twochar.Count(); n++)
            {
                string doublechar = twochar[n];
                ///STORE I AND J ////
                for (int k = 0; k < 2; k++)
                {
                    for (int i = 0; i < 5; i++)
                    {

                        for (int j = 0; j < 5; j++)
                        {
                            if (k == 0)
                            {
                                if (matrix[i, j] == doublechar[k])
                                {
                                    i1 = i;
                                    j1 = j;
                                }
                            }
                            else
                            {
                                if (matrix[i, j] == doublechar[k])
                                {
                                    i2 = i;
                                    j2 = j;
                                }

                            }
                        }

                    }

                }
                ///////////////////////////////////// encryption ALGO ////////////////////////////////////////////
                if (i1 == i2)
                {
                    j1 = (j1 + 1) % 5;
                    j2 = (j2 + 1) % 5;
                    encryptionstring.Append(matrix[i1, j1]);
                    encryptionstring.Append(matrix[i2, j2]);
                }
                else if (j2 == j1)
                {
                    i1 = (i1 + 1) % 5;
                    i2 = (i2 + 1) % 5;
                    encryptionstring.Append(matrix[i1, j1]);
                    encryptionstring.Append(matrix[i2, j2]);
                }
                else
                {
                    encryptionstring.Append(matrix[i1, j2]);
                    encryptionstring.Append(matrix[i2, j1]);

                }
                i1 = 0;
                j1 = 0;
                i2 = 0;
                j2 = 0;
            }

            string ciphertext = encryptionstring.ToString();
            return ciphertext;
        }
    }
}