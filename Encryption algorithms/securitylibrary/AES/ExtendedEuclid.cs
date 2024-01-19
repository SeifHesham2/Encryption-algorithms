using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        public int GetMultiplicativeInverse(int number, int baseN)
        {
            int[] A = new int[3];
            int[] B = new int[3];
            int[] T = new int[3];
            int Q;

            A[0] = 1; A[1] = 0; A[2] = baseN;
            B[0] = 0; B[1] = 1; B[2] = number;

            while (true)
            {
                if (B[2] == 0)
                    return -1;

                else if (B[2] == 1)
                {
                    if (B[1] < 0)
                        return B[1] + baseN;
                    else
                        return B[1];
                }

                Q = A[2] / B[2];
                T[0] = A[0] - Q * B[0]; T[1] = A[1] - Q * B[1]; T[2] = A[2] - Q * B[2];
                A[0] = B[0]; A[1] = B[1]; A[2] = B[2];
                B[0] = T[0]; B[1] = T[1]; B[2] = T[2];
            }
        }
    }
}