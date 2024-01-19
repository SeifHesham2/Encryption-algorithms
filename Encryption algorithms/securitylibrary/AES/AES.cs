using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        // Reading the matrices in the files.
        static string[,] SBox = Read("AESsBox.txt", 16, 16);
        static string[,] MixColumns = Read("MixColumns.txt", 4, 4);
        static string[,] Rcon = Read("RoundConst.txt", 4, 10);
        static string[,] InvSBox = Read("InvAESsBox.txt", 16, 16);
        static string[,] InvMixColumns = Read("InvMixColumns.txt", 4, 4);
        
        static string[,] LTable = Read("LTable.txt", 16, 16);
        static string[,] ETable = Read("ETable.txt", 16, 16);

        // Function to read a matrix from a text file.
        public static string[,] Read(string filePath, int N, int M)
        {
            string[,] file = new string[N, M]; // replace the dimensions as per your requirement

            // read the file contents using StreamReader
            using (StreamReader reader = new StreamReader(@filePath))
            {
                int i = 0, j = 0;
                while (!reader.EndOfStream)
                {
                    string line = reader.ReadLine();
                    string[] values = line.Split(' '); // assuming values are separated by space

                    foreach (string value in values)
                    {
                        file[i, j] = value;
                        j++;
                    }
                    i++;
                    j = 0;
                }
            }
            return file;
        }

        // Generic function to perform the generation of the 10 keys.
       

        static void ShiftRow(string[,] matrix, int rowIndex, int numShifts)
        {
            int numCols = matrix.GetLength(1);
            string[] row = new string[numCols];

            // Copy the row to a separate array
            for (int j = 0; j < numCols; j++)
                row[j] = matrix[rowIndex, j];

            // Shift the row by the specified number of positions
            for (int j = 0; j < numCols; j++)
            {
                int newIndex = (j + numShifts) % numCols;
                if (newIndex < 0)
                    newIndex += numCols;

                matrix[rowIndex, j] = row[newIndex];
            }
        }

        public static string Helper02(string[,] binaryPlain, int k, int j)
        {
            string xor = "";
            // Only do shift left (the 0 on the most left will be shifted to the most right).
            if (binaryPlain[k, j][0] == '0') // Significant bit 0
                xor = binaryPlain[k, j].Substring(1) + binaryPlain[k, j].Substring(0, 1);

            // Do shift left (remove the 1 on the most left and add 0 to the most right).
            // Then XOR the result from shifting with the given b1.
            else // Significant bit 1
            {
                string shiftLeft = binaryPlain[k, j].Substring(1) + "0";

                string b1 = "00011011";
                StringBuilder b1XORshifted = new StringBuilder();
                for (int m = 0; m < 8; m++)
                {
                    if (shiftLeft[m] == b1[m])
                        b1XORshifted.Append("0");
                    else
                        b1XORshifted.Append("1");
                }

                xor = b1XORshifted.ToString();
            }

            return xor;
        }

        public static string[,] MixColumn(string[,] plain)
        {
            string[,] binaryMixColumns = new string[4, 4];
            string[,] binaryPlain = new string[4, 4];

            // Converting the mix columns and plain matrices to binary representations.
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    binaryMixColumns[j, i] = Convert.ToString(Convert.ToInt32(MixColumns[j, i], 16), 2).PadLeft(8, '0');
                    binaryPlain[j, i] = Convert.ToString(Convert.ToInt32(plain[j, i], 16), 2).PadLeft(8, '0');
                }
            }

            string[,] result = new string[4, 4];
            // A string array that will contain the 4 results from XORing to XOR them again into one cell in the matrix.
            string[] xoring = new string[4];

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    for (int k = 0; k < 4; k++)
                    {
                        if (binaryMixColumns[i, k] == "00000010") // 02
                            xoring[k] = Helper02(binaryPlain, k, j);

                        else if (binaryMixColumns[i, k] == "00000011") // 03
                        {
                            // XORing with 02
                            string xor = Helper02(binaryPlain, k, j);

                            // XORing the result from above with the plain text itself.
                            StringBuilder sb = new StringBuilder();
                            for (int m = 0; m < 8; m++)
                            {
                                if (binaryPlain[k, j][m] == xor[m])
                                    sb.Append("0");
                                else
                                    sb.Append("1");
                            }

                            xoring[k] = sb.ToString();
                        }
                        else if (binaryMixColumns[i, k] == "00000001") // 01
                            xoring[k] = binaryPlain[k, j];
                    }

                    // XORing the 4 XORs from above to fit into one cell.
                    StringBuilder final = new StringBuilder();
                    int even = 0;

                    for (int m = 0; m < 8; m++)
                    {
                        even = 0;
                        for (int q = 0; q < 4; q++)
                            if (xoring[q][m] == '1') even++;

                        if (even % 2 == 0)
                            final.Append("0");
                        else
                            final.Append("1");
                    }

                    string hex = Convert.ToInt32(final.ToString(), 2).ToString("X2");
                    result[i, j] = hex;
                }
            }

            return result;
        }

        // Doing SubBytes to the whole matrix.
        public static string[,] SubBytes(string[,] text)
        {
            string[,] subMatrix = new string[4, 4];

            int row, col;
            for (int k = 0; k < 4; k++)
            {
                for (int i = 0; i < 4; i++)
                {
                    // Getting the row and column numbers from ASCII codes to index in the SBox.
                    row = (int)text[i, k][0];
                    col = (int)text[i, k][1];

                    if (row >= 65) row -= 55;
                    else row -= 48;

                    if (col >= 65) col -= 55;
                    else col -= 48;

                    subMatrix[i, k] = SBox[row, col];
                }
            }

            return subMatrix;
        }

        public static string[,] ROUND(string[,] text, string[,] key, bool lastRound)
        {
            string[,] subMatrix = SubBytes(text);

            ShiftRow(subMatrix, 1, 1);
            ShiftRow(subMatrix, 2, 2);
            ShiftRow(subMatrix, 3, 3);

            string[,] finalRound = new string[4, 4];

            // If we are in the 10th round, we ignore the MixColumn step.
            if (!lastRound)
            {
                string[,] mixedMatrix = MixColumn(subMatrix);
                finalRound = AddRoundKey(mixedMatrix, key);
            }
            else
                finalRound = AddRoundKey(subMatrix, key);

            return finalRound;
        }
        /*
         * function of Decrypt
         */

        // Generic function to perform the generation of the 10 keys.
      
      

        public static string XOR(string A, string B)
        {
            if (A == "") return B;
            char[] output = new char[8];
            for (int i = 0; i < A.Length; i++)
            {
                if (A.Substring(i, 1) == B.Substring(i, 1)) output[i] = '0';
                else output[i] = '1';
            }
            return new string(output);
        }
        public static string multInvMixColumns(string A, string B)
        {
      
            if (A.Length < 2) A = "0" + A;
            if (B.Length < 2) B = "0" + B;
            if (A == "00" || B == "00") return "00";
            int row1 = Convert.ToInt32(A.Substring(0, 1), 16);
            int col1 = Convert.ToInt32(A.Substring(1, 1), 16);

            int row2 = Convert.ToInt32(B.Substring(0, 1), 16);
            int col2 = Convert.ToInt32(B.Substring(1, 1), 16);

            int sum = Convert.ToInt32(LTable[row1, col1], 16) + Convert.ToInt32(LTable[row2, col2], 16);
            if (sum > Convert.ToInt32("FF", 16))
            {
                sum = sum - Convert.ToInt32("FF", 16);
            }
            string ans = sum.ToString("X2");
            int row = Convert.ToInt32(ans.Substring(0, 1), 16);
            int col = Convert.ToInt32(ans.Substring(1, 1), 16);
            return ETable[row, col];
        }
        public static string[,] invmixColumns(string[,] state)
        {
            for (int col = 0; col < 4; col++)
            {
                string[,] tempState = new string[4, 1];
                for (int i = 0; i < 4; i++)
                {
                    tempState[i, 0] = state[i, col];
                }

                string[,] tempColMixMatrix = new string[4, 1];

                for (int i = 0; i < 4; i++)
                {
                    for (int z = 0; z < 4; z++)
                    {
                        tempColMixMatrix[z, 0] = InvMixColumns[i, z];
                    }
                    string temp = "";
                    for (int j = 0; j < 4; j++)
                    {
                        string ans = multInvMixColumns(tempColMixMatrix[j, 0], tempState[j, 0]);
                        ans = Convert.ToString(Convert.ToInt32(ans, 16), 2).PadLeft(8, '0');
                        temp = XOR(temp, ans);
                    }
                    state[i, col] = Convert.ToString(Convert.ToInt32(temp, 2), 16);
                }
            }
            return state;
        }




        public static string[,] KeyScheduling(string[,] key, int index)
        {
            string[,] matrix = new string[4, 4];

            // Rotating the first word to the last.
            matrix[0, 0] = key[1, 3];
            matrix[1, 0] = key[2, 3];
            matrix[2, 0] = key[3, 3];
            matrix[3, 0] = key[0, 3];

            int row, col;
            for (int i = 0; i < 4; i++)
            {
                // Getting the row and column numbers from ASCII codes to index in the SBox.
                row = (int)matrix[i, 0][0];
                col = (int)matrix[i, 0][1];

                if (row >= 65) row -= 55;
                else row -= 48;

                if (col >= 65) col -= 55;
                else col -= 48;

                matrix[i, 0] = SBox[row, col];
            }

            // XORing between the first column of the matrix and the first column in the key.
            StringBuilder XOR = new StringBuilder();
            for (int i = 0; i < 4; i++)
            {
                string binary1 = Convert.ToString(Convert.ToInt32(matrix[i, 0], 16), 2).PadLeft(8, '0');
                string binary2 = Convert.ToString(Convert.ToInt32(key[i, 0], 16), 2).PadLeft(8, '0');

                for (int j = 0; j < 8; j++)
                {
                    if (binary1[j] == binary2[j])
                        XOR.Append("0");
                    else
                        XOR.Append("1");
                }
            }

            // XORing between the XOR done above and the RoundConst matching column.
            StringBuilder XOR2 = new StringBuilder();
            for (int i = 0; i < 4; i++)
            {
                string rconCol = Rcon[i, index];
                string binary = Convert.ToString(Convert.ToInt32(rconCol, 16), 2).PadLeft(8, '0');
                string split = XOR.ToString().Substring(i * 8, 8);

                for (int j = 0; j < 8; j++)
                {
                    if (binary[j] == split[j])
                        XOR2.Append("0");
                    else
                        XOR2.Append("1");
                }
            }

            // Converting the binary number to hexadecimal representation.
            string binaryString = XOR2.ToString();
            string hex = "";

            for (int i = 0; i < binaryString.Length; i += 4)
            {
                string binarySubstring = binaryString.Substring(i, 4);
                int decimalValue = Convert.ToInt32(binarySubstring, 2);
                string hexSubstring = decimalValue.ToString("X");
                hex += hexSubstring;
            }

            // Filling the first column in the generated key with our result.
            for (int i = 0; i < 4; i++)
                matrix[i, 0] = hex.Substring((i * 2), 2);

            // Filling the 3 next columns in the key matrix with the same method.
            for (int k = 1; k < 4; k++)
            {
                StringBuilder MatrixXORlastcolumn = new StringBuilder();
                for (int i = 0; i < 4; i++)
                {
                    MatrixXORlastcolumn.Clear();
                    string binary1 = Convert.ToString(Convert.ToInt32(matrix[i, k - 1], 16), 2).PadLeft(8, '0');
                    string binary2 = Convert.ToString(Convert.ToInt32(key[i, k], 16), 2).PadLeft(8, '0');

                    for (int j = 0; j < 8; j++)
                    {
                        if (binary1[j] == binary2[j])
                            MatrixXORlastcolumn.Append("0");
                        else
                            MatrixXORlastcolumn.Append("1");
                    }

                    // Converting the binary number to hexadecimal representation.
                    string binaryString2 = MatrixXORlastcolumn.ToString();
                    string hexx = "";

                    for (int a = 0; a < binaryString2.Length; a += 4)
                    {
                        string binarySubstring = binaryString2.Substring(a, 4);
                        int decimalValue = Convert.ToInt32(binarySubstring, 2);
                        string hexSubstring = decimalValue.ToString("X");
                        hexx += hexSubstring;
                    }

                    // Filling one cell in the column with our result.
                    matrix[i, k] = hexx;
                }
            }

            return matrix;
        }

        public static string[,] AddRoundKey(string[,] text, string[,] key)
        {
            string[,] matrix = new string[4, 4];

            // XORing between each column in the plain text with its corresponding column in the key.
            for (int k = 0; k < 4; k++)
            {
                StringBuilder textXORkey = new StringBuilder();
                for (int i = 0; i < 4; i++)
                {
                    textXORkey.Clear();
                    string binary1 = Convert.ToString(Convert.ToInt32(text[i, k], 16), 2).PadLeft(8, '0');
                    string binary2 = Convert.ToString(Convert.ToInt32(key[i, k], 16), 2).PadLeft(8, '0');

                    for (int j = 0; j < 8; j++)
                    {
                        if (binary1[j] == binary2[j])
                            textXORkey.Append("0");
                        else
                            textXORkey.Append("1");
                    }

                    string hex = Convert.ToInt32(textXORkey.ToString(), 2).ToString("X2");

                    // Filling one cell in the column with our result.
                    matrix[i, k] = hex;
                }
            }

            return matrix;
        }

        static string[,] invsBoxSub(string[,] finalMatrix)
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string cell = finalMatrix[i, j];
                    if (cell.Length == 1)
                    {
                        cell = "0" + cell;
                    }
                    int row = Convert.ToInt32(cell.Substring(0, 1), 16);
                    int col = Convert.ToInt32(cell.Substring(1, 1), 16);
                    finalMatrix[i, j] = InvSBox[row, col];
                }
            }
            return finalMatrix;
        }

        public static string[,] InvSubBytes(string[,] text)
        {
            string[,] subMatrix = new string[4, 4];

            int row, col;
            for (int k = 0; k < 4; k++)
            {
                for (int i = 0; i < 4; i++)
                {
                    // Getting the row and column numbers from ASCII codes to index in the SBox.
                    row = (int)text[i, k][0];
                    col = (int)text[i, k][1];

                    if (row >= 65) row -= 55;
                    else row -= 48;

                    if (col >= 65) col -= 55;
                    else col -= 48;

                    subMatrix[i, k] = InvSBox[row, col];
                }
            }

            return subMatrix;
        }

        static void InvShiftRow(string[,] matrix, int rowIndex, int numShifts)
        {
            int numCols = matrix.GetLength(1);
            string[] row = new string[numCols];

            // Copy the row to a separate array
            for (int j = 0; j < numCols; j++)
                row[j] = matrix[rowIndex, j];

            // Unshift the row by the opposite number of positions
            for (int j = 0; j < numCols; j++)
            {
                int newIndex = (j - numShifts) % numCols;
                if (newIndex < 0)
                    newIndex += numCols;

                matrix[rowIndex, j] = row[newIndex];
            }
        }

        public static string[,] ROUND_Dec(string[,] text, string[,] key, bool lastRound)
        {
            string[,] finalRound = new string[4, 4];
            string[,] subMatrix = AddRoundKey(text, key);

            // If we are in the 10th round, we ignore the MixColumn step.
            if (lastRound == false)
            {
                string[,] mixedMatrix = invmixColumns(subMatrix);
                InvShiftRow(mixedMatrix, 1, 1);
                InvShiftRow(mixedMatrix, 2, 2);
                InvShiftRow(mixedMatrix, 3, 3);
            }
            else
            {
                InvShiftRow(subMatrix, 1, 1);
                InvShiftRow(subMatrix, 2, 2);
                InvShiftRow(subMatrix, 3, 3);

            }
            finalRound = invsBoxSub(subMatrix);

            return finalRound;
        }

        public override string Decrypt(string cipherText, string key)
        {
            bool upperCase = true;
            if (key == key.ToLower())
            {
                upperCase = false;
                key = key.ToUpper();
                cipherText = cipherText.ToUpper();
            }

            // Removing the 0x in the beginning of the given strings.
            key = key.Substring(2, key.Length - 2);
            cipherText = cipherText.Substring(2, cipherText.Length - 2);

            // Splitting the key two a string array of two letters each (to be put in a 4x4 key matrix).
            string[] keySplit = new string[16];
            for (int i = 0; i < 16; i++)
                keySplit[i] = key.Substring(i * 2, 2);

            // Filling the key array in a 4x4 key matrix (by column).
            string[,] keyMatrix = new string[4, 4];
            int c = 0;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    keyMatrix[j, i] = keySplit[c];
                    c++;
                }
            }

            // Making a string array of 2D arrays containing the 10 generated keys (and the initial key as the first one).
            string[][,] arr3D = new string[11][,];
            arr3D[0] = keyMatrix;
            for (int i = 1; i < 11; i++)
                arr3D[i] = KeyScheduling(arr3D[i - 1], i - 1);

            // Splitting the cipher text two a string array of two letters each (to be put in a 4x4 plain matrix).
            string[] cipherMatrix = new string[16];
            for (int i = 0; i < 16; i++)
                cipherMatrix[i] = cipherText.Substring(i * 2, 2);

            // Filling the cipher array in a 4x4 plain matrix (by column).
            string[,] cipher = new string[4, 4];
            c = 0;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    cipher[j, i] = cipherMatrix[c];
                    c++;
                }
            }

            // Now, we are ready to start the decryption process with the 4x4 cipher text and key matrices.

            // Round 10: The same as the 9 rounds but without the InvMixColumns.
            string[,] roundText = ROUND_Dec(cipher, arr3D[10], true);

            // We do 9 rounds of decryption (SubBytes, ShiftRows, InvMixColumns, AddRoundKey).
            for (int i = 9; i >= 1; i--)
                roundText = ROUND_Dec(roundText, arr3D[i], false);

            // We do one AddRoundKey first with out initial plain text and key.
            string[,] final = AddRoundKey(roundText, arr3D[0]);


            // If the strings were in lower case, we re-convert them to lower case for the tests to pass.
            if (!upperCase)
            {
                for (int i = 0; i < 4; i++)
                    for (int j = 0; j < 4; j++)
                        final[i, j] = final[i, j].ToLower();
            }

            StringBuilder plainText = new StringBuilder();
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    plainText.Append(final[j, i]);

            string plain = "0x" + plainText.ToString();
            
            return plain;
        }
        
        public override string Encrypt(string plainText, string key)
        {
            // To check if the given test is in upper case or lower case.
            bool upperCase = true;
            if (key == key.ToLower())
            {
                upperCase = false;
                key = key.ToUpper();
                plainText = plainText.ToUpper();
            }

            // Removing the 0x in the beginning of the given strings.
            key = key.Substring(2, key.Length - 2);
            plainText = plainText.Substring(2, plainText.Length - 2);

            // Splitting the key two a string array of two letters each (to be put in a 4x4 key matrix).
            string[] keySplit = new string[16];
            for (int i = 0; i < 16; i++)
                keySplit[i] = key.Substring(i * 2, 2);

            // Filling the key array in a 4x4 key matrix (by column).
            string[,] keyMatrix = new string[4, 4];
            int c = 0;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    keyMatrix[j, i] = keySplit[c];
                    c++;
                }
            }

            // Making a string array of 2D arrays containing the 10 generated keys (and the initial key as the first one).
            string[][,] arr3D = new string[11][,];
            arr3D[0] = keyMatrix;
            for (int i = 1; i < 11; i++)
                arr3D[i] = KeyScheduling(arr3D[i - 1], i - 1);

            // Splitting the plain text two a string array of two letters each (to be put in a 4x4 plain matrix).
            string[] plainMatrix = new string[16];
            for (int i = 0; i < 16; i++)
                plainMatrix[i] = plainText.Substring(i * 2, 2);

            // Filling the plain array in a 4x4 plain matrix (by column).
            string[,] plain = new string[4, 4];
            c = 0;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    plain[j, i] = plainMatrix[c];
                    c++;
                }
            }

            // Now, we are ready to start the encryption process with the 4x4 plain text and key matrices.

            // We do one AddRoundKey first with out initial plain text and key.
            string[,] roundText = AddRoundKey(plain, arr3D[0]);

            // We do 9 rounds of encryption (SubBytes, ShiftRows, MixColumns, AddRoundKey).
            for (int i = 1; i <= 9; i++)
                roundText = ROUND(roundText, arr3D[i], false);

            // Round 10: The same as the 9 rounds but without the MixColumns.
            string[,] final = ROUND(roundText, arr3D[10], true);

            // If the strings were in lower case, we re-convert them to lower case for the tests to pass.
            if (!upperCase)
            {
                for (int i = 0; i < 4; i++)
                    for (int j = 0; j < 4; j++)
                        final[i, j] = final[i, j].ToLower();
            }

            StringBuilder cipherText = new StringBuilder();
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    cipherText.Append(final[j, i]);

            string cipher = "0x" + cipherText.ToString();
            return cipher;
        }
    }
}