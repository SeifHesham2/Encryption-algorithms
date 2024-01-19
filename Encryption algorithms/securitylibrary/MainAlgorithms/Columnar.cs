using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();

            cipherText = cipherText.ToLower();
            int plainLength = plainText.Length;
            List<int> colNumbers = new List<int>() { 1 };
            List<int> Key = new List<int>();

            for (int k = 2; k < plainLength; k++)
            {
                colNumbers.Add(k);

                int numCols = k;
                double numRows = (int)Math.Ceiling((double)plainText.Length / (double)numCols);

                // If the plain text won't fill the entire matrix, we mark fullMatrix boolean as false.
                bool fullMatrix = true;
                int difference = ((int)numRows * numCols) - cipherText.Length;
                if (difference != 0) fullMatrix = false;

                // Making an array of string builders as to put every column letters into a single string to compare the cipher text with it.
                StringBuilder[] cols = new StringBuilder[numCols];
                for (int ix = 0; ix < numCols; ++ix)
                    cols[ix] = new StringBuilder();

                char[,] charMatrix = new char[(int)numRows, numCols];
                for (int i = 0; i < numRows; i++)
                    for (int j = 0; j < numCols; j++)
                    {
                        if (i * numCols + j >= plainText.Length) // If we exceeded the plain text length
                            break;
                        else
                            charMatrix[i, j] = plainText[i * numCols + j];

                        cols[j].Append(charMatrix[i, j]);
                    }


                int start = 0;
                int end = (int)numRows;
                List<int> copyOfColNumbers = new List<int>(colNumbers);
                List<int> realKey = new List<int>();

                // Checking loop
                for (int i = 0; i < numCols; i++)
                {
                    foreach (var colNum in copyOfColNumbers)
                    {
                        string inCol = cols[colNum - 1].ToString();
                        end = (int)numRows;

                        // If our matrix isn't full, and we reached the column where the last row is empty, we check on number of letters - 1 (to fit in this column).
                        if (!fullMatrix && colNum >= (numCols - difference + 1)) end -= 1;
                        
                        string inCipher = cipherText.Substring(start, end);

                        if (String.Equals(inCipher, inCol))
                        {
                            copyOfColNumbers.Remove(colNum);
                            realKey.Add(colNum);

                            if (end == (int)numRows - 1)
                            {
                                start += (int)numRows - 1;
                                end++;
                            }
                            else start += (int)numRows;
                            break;
                        }
                    }
                }

                // If we correctly analyzed the algorithm, exit from the loop returning the correct order of the key.
                if (realKey.Count == numCols)
                {
                    int[] orderedKey = new int[numCols];
                    int counter = 1;
                    foreach (var index in realKey)
                    {
                        orderedKey[index - 1] = counter;
                        counter++;
                    }

                    Key.AddRange(orderedKey);
                    break;
                }
            }

            return Key;
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            //throw new NotImplementedException();

            int numCols = key.Count; // Key Length
            double numRows = (int)Math.Ceiling((double)cipherText.Length / (double)numCols);

            // If the cipher text won't fill the entire matrix, we mark fullMatrix boolean as false.
            bool fullMatrix = true;
            int difference = ((int)numRows * numCols) - cipherText.Length;
            if (difference != 0) fullMatrix = false;

            char[,] charMatrix = new char[(int)numRows, numCols];

            // Ordering the key so we can go from index 0 to index N easily.
            int[] orderedKey = new int[numCols];
            int counter = 1;
            foreach (var index in key)
            {
                orderedKey[index - 1] = counter;
                counter++;
            }

            int cipherLength = 0;
            for (int i = 0; i < numCols; i++)
                for (int j = 0; j < numRows; j++)
                {
                    // If our cipher text length won't fill the entire matrix, a condition is made to check if it is writing in the last row in the last few columns, it doesn't write in it and break from the loop.
                    if (!fullMatrix && orderedKey[i] >= (numCols - difference + 1) && j == numRows - 1) break;

                    if (cipherLength >= cipherText.Length) break;
                    else
                        charMatrix[j, orderedKey[i] - 1] = cipherText[cipherLength++];
                }

            StringBuilder plainText = new StringBuilder();
            for (int i = 0; i < numRows; i++)
                for (int j = 0; j < numCols; j++)
                    plainText.Append(charMatrix[i, j]);

            return plainText.ToString();
        }

        public string Encrypt(string plainText, List<int> key)
        {
            //throw new NotImplementedException();

            int numCols = key.Count; // Key Length
            double numRows = (int)Math.Ceiling((double)plainText.Length / (double)numCols);

            char[,] charMatrix = new char[(int)numRows, numCols];

            for (int i = 0; i < numRows; i++)
                for (int j = 0; j < numCols; j++)
                {
                    if (i * numCols + j >= plainText.Length) // If we exceeded the plain text length
                        break;
                    else
                        charMatrix[i, j] = plainText[i * numCols + j];
                }

            // Ordering the key so we can go from index 0 to index N easily.
            int[] orderedKey = new int[numCols];
            int counter = 1;
            foreach (var index in key)
            {
                orderedKey[index - 1] = counter;
                counter++;
            }

            StringBuilder cipherText = new StringBuilder();
            for (int i = 0; i < numCols; i++)
                for (int j = 0; j < numRows; j++)
                    cipherText.Append(charMatrix[j, orderedKey[i] - 1]);

            return cipherText.ToString();
        }
    }
}
