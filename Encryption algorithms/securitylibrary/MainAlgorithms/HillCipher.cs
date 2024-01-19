using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            //throw new NotImplementedException();
            List<int> returned_cipher = new List<int>();
            List<int> key1 = new List<int>();

            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    for (int k = 0; k < 26; k++)
                    {
                        for (int l = 0; l < 26; l++)
                        {
                            key1 = new List<int> { l, k, j, i };
                            returned_cipher = Encrypt(plainText, key1);

                            /*here we compare the returned cipher and cipher text 
                            if both are equal we return the key*/
                            if (returned_cipher.SequenceEqual(cipherText))
                                return key1;
                        }
                    }
                }
            }
            // we throw an exception if we could not find the key
            throw new InvalidAnlysisException();
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            //throw new NotImplementedException();
            int rows = (int)Math.Sqrt(key.Count());
            int cols = cipherText.Count() / rows;
            List<int> cipherTxt = new List<int>();
            int det = 0;
            int index = 0;
            int[,] key1 = new int[rows, rows];
            int multiplicative_inverse = 0;

            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < rows; j++)
                {
                    key1[i, j] = key[index];
                    index++;
                }
            }

            index = 0;
            int[,] cipher = new int[cols, rows];

            for (int i = 0; i < cols; i++)
            {
                for (int j = 0; j < rows; j++)
                {
                    cipher[i, j] = cipherText[index];
                    index++;
                }
            }

            //2*2 matrix
            /* 
               1- find the det
               2- get the inverse key matrix   
               3- multiply det * inverse key matrix
               4- then take the result and multiply it by cipher matrix
             */

            if (rows % 2 == 0)
            {
                int GCD = 1;
                det += (key1[0, 0] * key1[1, 1]) - (key1[1, 0] * key1[0, 1]);
                for (int i = 2; i <= det; i++)
                {
                    if (26 % i == 0 && det % i == 0)
                        GCD = i;
                }

                if (det == 0 || GCD != 1)
                    throw new Exception();

                //get the inverse of key matrix
                int temp = 0;
                temp = key1[0, 0];
                key1[0, 0] = key1[1, 1];
                key1[1, 1] = temp;
                key1[0, 1] *= -1;
                key1[1, 0] *= -1;

                //Apply rule kij ={b x (-1)i+j * Dij mod 26}
                for (int i = 0; i < rows; i++)
                {
                    for (int j = 0; j < rows; j++)
                    {
                        key1[i, j] = (int)Math.Pow(det, -1) * key1[i, j];
                    }
                }

                int sum = 0;
                for (int j = 0; j < cols; j++)
                {
                    for (int i = 0; i < rows; i++)
                    {
                        sum = 0;
                        for (int k = 0; k < rows; k++)
                        {
                            sum += cipher[j, k] * key1[i, k];
                        }
                        if (sum < 0)
                        {

                            sum = 26 - (sum * -1) % 26;
                            cipherTxt.Add(sum);
                        }
                        else
                        {
                            sum = sum % 26;
                            cipherTxt.Add(sum);
                        }
                    }
                }
            }

            // 3*3 matrix
            /*
             * 1- det 
             * 2- multiplicative_inverse 
             * 3- multiplicative_inverse * matrix 
             * 4- transpose inverse matrix
             * 5- matrix transpose * cipher 
             */

            else
            {
                for (int i = 0; i < rows; i++)
                {
                    det += (key1[0, i] * (key1[1, (i + 1) % 3] * key1[2, (i + 2) % 3] -
                            key1[1, (i + 2) % 3] * key1[2, (i + 1) % 3]));
                }
                if (det < 0)
                    det = (26 - (-1 * det % 26));
                else
                    det = det % 26;

                int GCD = 1;
                for (int i = 2; i <= det; i++)
                {
                    if (26 % i == 0 && det % i == 0)
                        GCD = i;
                }

                if (det == 0 || GCD != 1)
                    throw new Exception();

                for (int i = 1; i < 26; i++)
                {
                    if (det * i % 26 == 1)
                    {
                        multiplicative_inverse = i;
                        break;
                    }
                }

                List<int> inverse_key = new List<int>();
                for (int i = 0; i < rows; i++)
                {
                    int result = multiplicative_inverse * ((key1[1, (i + 1) % 3] * key1[2, (i + 2) % 3] -
                     key1[1, (i + 2) % 3] * key1[2, (i + 1) % 3]));
                    if (result < 0)
                        result = (26 - (-1 * result) % 26);
                    else
                        result %= 26;
                    inverse_key.Add(result);
                }

                for (int i = 0; i < rows; i++)
                {
                    int value = multiplicative_inverse;
                    int result = value * ((key1[2, (i + 1) % 3] * key1[0, (i + 2) % 3] -
                     key1[2, (i + 2) % 3] * key1[0, (i + 1) % 3]));
                    if (result < 0)
                        result = (26 - (-1 * result) % 26);
                    else
                        result %= 26;
                    inverse_key.Add(result);
                }

                for (int i = 0; i < rows; i++)
                {
                    int value = multiplicative_inverse;
                    int result = value * ((key1[0, (i + 1) % 3] * key1[1, (i + 2) % 3] -
                     key1[0, (i + 2) % 3] * key1[1, (i + 1) % 3]));
                    if (result < 0)
                        result = (26 - (-1 * result) % 26);
                    else
                        result %= 26;
                    inverse_key.Add(result);
                }

                index = 0;
                int[,] arr = new int[rows, rows];
                for (int i = 0; i < rows; i++)
                {
                    for (int j = 0; j < rows; j++)
                    {
                        arr[j, i] = inverse_key[index];
                        index++;
                    }
                }

                int sum;
                for (int j = 0; j < cols; j++)
                {
                    for (int i = 0; i < rows; i++)
                    {
                        sum = 0;
                        for (int k = 0; k < rows; k++)
                        {
                            sum += cipher[j, k] * arr[i, k];
                        }
                        if (sum < 0)
                        {

                            sum = 26 - (sum * -1) % 26;
                            cipherTxt.Add(sum);
                        }
                        else
                        {
                            sum = sum % 26;
                            cipherTxt.Add(sum);
                        }

                    }
                }

            }
            return cipherTxt;
        }

        public string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            //throw new NotImplementedException();
            int number_rows = (int)Math.Sqrt(key.Count());
            int number_cols = plainText.Count() / number_rows;
            int[,] plain1 = new int[number_rows, number_cols];
            int[,] key1 = new int[number_rows, number_rows];
            List<int> cipher1 = new List<int>();

            int index = 0;
            for (int j = 0; j < number_cols; j++)
            {
                for (int i = 0; i < number_rows; i++)
                {

                    plain1[i, j] = plainText[index];
                    index++;
                }
            }

            index = 0;
            for (int i = 0; i < number_rows; i++)
            {
                for (int j = 0; j < number_rows; j++)
                {
                    key1[i, j] = key[index];
                    index++;
                }
            }

            int sum = 0;
            for (int j = 0; j < number_cols; j++)
            {
                for (int i = 0; i < number_rows; i++)
                {
                    sum = 0;
                    for (int k = 0; k < number_rows; k++)
                    {

                        sum += key1[i, k] * plain1[k, j];

                    }
                    cipher1.Add(sum % 26);
                }
            }
            return cipher1;
        }
        public string Encrypt(string plainText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            //  throw new NotImplementedException();
            int[,] cipher = new int[3, 3];
            /*
             * 1- cipher 
             * 2- inverse plain
             *   2.1- det
             *   2.2- multiplicative
             *   2.3- multiplicative * plain
             *   2.4- transpose matrix
             *   
             * 3- cipher * matrix mod26 
             */
            int index = 0;
            int[,] plain = new int[3, 3];
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    plain[i, j] = plain3[index];
                    index++;
                }
            }

            index = 0;
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    cipher[i, j] = cipher3[index];
                    index++;
                }
            }

            int det = 0;

            for (int i = 0; i < 3; i++)
            {
                det += (plain[0, i] * (plain[1, (i + 1) % 3] * plain[2, (i + 2) % 3] -
                        plain[1, (i + 2) % 3] * plain[2, (i + 1) % 3]));
            }
            if (det < 0)
                det = (26 - (-1 * det % 26));
            else
                det = det % 26;

            int GCD = 1;
            for (int i = 2; i <= det; i++)
            {
                if (26 % i == 0 && det % i == 0)
                    GCD = i;
            }

            if (det == 0 || GCD != 1)
                throw new Exception();

            int multiplicative_inverse = 0;
            for (int i = 1; i < 26; i++)
            {
                if (det * i % 26 == 1)
                {
                    multiplicative_inverse = i;
                    break;
                }
            }

            List<int> inverse_plain = new List<int>();
            for (int i = 0; i < 3; i++)
            {
                int result = multiplicative_inverse * ((plain[1, (i + 1) % 3] * plain[2, (i + 2) % 3] -
                 plain[1, (i + 2) % 3] * plain[2, (i + 1) % 3]));
                if (result < 0)
                    result = (26 - (-1 * result) % 26);
                else
                    result %= 26;
                inverse_plain.Add(result);
            }

            for (int i = 0; i < 3; i++)
            {
                int value = multiplicative_inverse;
                int result = value * ((plain[2, (i + 1) % 3] * plain[0, (i + 2) % 3] -
                 plain[2, (i + 2) % 3] * plain[0, (i + 1) % 3]));
                if (result < 0)
                    result = (26 - (-1 * result) % 26);
                else
                    result %= 26;
                inverse_plain.Add(result);
            }

            for (int i = 0; i < 3; i++)
            {
                int value = multiplicative_inverse;
                int result = value * ((plain[0, (i + 1) % 3] * plain[1, (i + 2) % 3] -
                 plain[0, (i + 2) % 3] * plain[1, (i + 1) % 3]));
                if (result < 0)
                    result = (26 - (-1 * result) % 26);
                else
                    result %= 26;
                inverse_plain.Add(result);
            }

            index = 0;
            int[,] arr = new int[3, 3];
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    arr[j, i] = inverse_plain[index];
                    index++;
                }
            }

            int sum;
            List<int> keylist = new List<int>();
            for (int j = 0; j < 3; j++)
            {
                for (int i = 0; i < 3; i++)
                {
                    sum = 0;
                    for (int k = 0; k < 3; k++)
                    {

                        sum += cipher[k, j] * arr[i, k];
                    }
                    if (sum < 0)
                    {
                        sum = 26 - (sum * -1) % 26;
                        keylist.Add(sum);
                    }
                    else
                    {
                        sum = sum % 26;
                        keylist.Add(sum);
                    }

                }
            }
            return keylist;
        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {
            throw new NotImplementedException();
        }
    }
}
