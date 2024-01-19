using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {
        // Reading the matrices in the files.
        static int[,] PC1 = Read("PC1.txt", 8, 7);
        static int[,] PC2 = Read("PC2.txt", 8, 6);
        static int[,] IP = Read("IP.txt", 8, 8);
        static int[,] IPinverse = Read("IP-1.txt", 8, 8);
        static int[,] Expansion = Read("Expansion.txt", 8, 6);
        static int[,] P = Read("P.txt", 8, 4);
        static int[,] S1 = Read("S1.txt", 4, 16);
        static int[,] S2 = Read("S2.txt", 4, 16);
        static int[,] S3 = Read("S3.txt", 4, 16);
        static int[,] S4 = Read("S4.txt", 4, 16);
        static int[,] S5 = Read("S5.txt", 4, 16);
        static int[,] S6 = Read("S6.txt", 4, 16);
        static int[,] S7 = Read("S7.txt", 4, 16);
        static int[,] S8 = Read("S8.txt", 4, 16);
        static List<int[,]> SBoxArray = new List<int[,]>() { S1, S2, S3, S4, S5, S6, S7, S8 };
        static int[,] numberOfLeftShifts = Read("NumberOfLeftShifts.txt", 16, 2);

        // Function to read a matrix from a text file.
        public static int[,] Read(string filePath, int N, int M)
        {
            int[,] file = new int[N, M]; // replace the dimensions as per your requirement

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
                        file[i, j] = int.Parse(value);
                        j++;
                    }
                    i++;
                    j = 0;
                }
            }
            return file;
        }

        // Generic function to perform the matrix indexing.
        public static string Generic(int N, int M, string x, int[,] file)
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < N; i++)
                for (int j = 0; j < M; j++)
                    sb.Append(x[file[i, j] - 1]);

            return sb.ToString();
        }

        // Shifting binary numbers to left by the "shiftAmount".
        public static string ShiftLeft(string key, int shiftAmount)
        {
            return key.Substring(shiftAmount) + key.Substring(0, shiftAmount);
        }

        public static string[] Round(string text, string key)
        {
            string L = text.Substring(0, 32);
            string R = text.Substring(32, 32);
            string e = Generic(8, 6, R, Expansion); // 48-bit

            // XORing the output from the expansion with the key from PC2.
            StringBuilder ExpansionXORKey = new StringBuilder();
            for (int i = 0; i < 48; i++)
            {
                if (e[i] == key[i])
                    ExpansionXORKey.Append("0");
                else
                    ExpansionXORKey.Append("1");
            }
            string eXORk = ExpansionXORKey.ToString();

            // Dividing the output of the XOR to 8 blocks of 6-bits each to be given to the S boxes.
            string[] sBoxArray = new string[8];
            int c = 0;
            for (int i = 0; i < 48; i += 6)
            {
                sBoxArray[c] = eXORk.Substring(i, 6);
                c++;
            }

            string col, row;
            StringBuilder Sbox = new StringBuilder();
            //Doing the S Box function.
            for (int i = 0; i < 8; i++)
            {
                row = sBoxArray[i].Substring(0, 1) + sBoxArray[i].Substring(5);
                col = sBoxArray[i].Substring(1, 4);

                int rowNum = Convert.ToInt32(row, 2);
                int colNum = Convert.ToInt32(col, 2);

                int index = SBoxArray[i][rowNum, colNum];

                string binary = Convert.ToString(index, 2).PadLeft(4, '0');
                Sbox.Append(binary); // 32-bit
            }

            string p = Generic(8, 4, Sbox.ToString(), P); // 32-bit

            // XORing the output from the S boxes with the L from the previous round.
            StringBuilder SboxXORL = new StringBuilder();
            for (int i = 0; i < 32; i++)
            {
                if (p[i] == L[i])
                    SboxXORL.Append("0");
                else
                    SboxXORL.Append("1");
            }

            string newR = SboxXORL.ToString();
            string newL = R;

            string[] LR = { newL, newR };

            return LR;
        }

        // Generic function for encryption and decryption (as they are the same code).
        public static string EncryptionDecryption(string text, string key, bool encrypt)
        {
            //throw new NotImplementedException();

            string Text = text.Substring(2, text.Length - 2);
            string binaryText = string.Join(String.Empty, Text.Select(c => Convert.ToString(Convert.ToInt32(c.ToString(), 16), 2).PadLeft(4, '0')));

            string k = key.Substring(2, key.Length - 2);
            string binaryKey = string.Join(String.Empty, k.Select(c => Convert.ToString(Convert.ToInt32(c.ToString(), 16), 2).PadLeft(4, '0')));

            string afterPC1 = Generic(8, 7, binaryKey, PC1); //56-bit

            string C = afterPC1.Substring(0, 28);
            string D = afterPC1.Substring(28, 28);

            string[] cArray = new string[16];
            string[] dArray = new string[16];

            for (int i = 0; i < 16; i++)
            {
                cArray[i] = ShiftLeft(C, numberOfLeftShifts[i, 1]);
                C = cArray[i];
            }
            for (int i = 0; i < 16; i++)
            {
                dArray[i] = ShiftLeft(D, numberOfLeftShifts[i, 1]);
                D = dArray[i];
            }

            string[] pc2Array = new string[16];
            for (int i = 0; i < 16; i++)
            {
                string x = cArray[i] + dArray[i];
                pc2Array[i] = Generic(8, 6, x, PC2); // 48-bit
            }

            string ip = Generic(8, 8, binaryText, IP); // 64-bit
            if (encrypt)
            {
                for (int i = 0; i < 16; i++)
                {
                    string[] LR = Round(ip, pc2Array[i]); // 64-bit
                    ip = LR[0] + LR[1];
                }
            }
            else // decrypt
            {
                for (int i = 15; i >= 0; i--)
                {
                    string[] LR = Round(ip, pc2Array[i]); // 64-bit
                    ip = LR[0] + LR[1];
                }
            }

            string swap = ip.Substring(32, 32) + ip.Substring(0, 32);
            string generatedText = Generic(8, 8, swap, IPinverse); // 64-bit

            byte[] bytes = new byte[8];
            for (int i = 0; i < 8; i++)
                bytes[i] = Convert.ToByte(generatedText.Substring(i * 8, 8), 2);

            string hexString = BitConverter.ToString(bytes).Replace("-", "");

            hexString = "0x" + hexString;

            return hexString;
        }

        public override string Decrypt(string cipherText, string key)
        {
            return EncryptionDecryption(cipherText, key, false);
        }
        public override string Encrypt(string plainText, string key)
        {
            return EncryptionDecryption(plainText, key, true);
        }
    }
}