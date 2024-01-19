using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public static int Pow(int b, int e, int m)
        {
            int result = 1;

            while (e > 0)
            {
                if ((e & 1) == 1)
                {
                    long x = (long)result;
                    long y = (long)b;
                    long res = x * y;
                    
                    res %= m;
                    result = (int)(res);
                }

                long z = (long)b;
                long f = (long)b;
                long res2 = z * f;
                
                res2 %= m;
                b = (int)(res2);
                e /= 2;
            }

            return result;
        }

        public int Encrypt(int p, int q, int M, int e)
        {
            int x = p * q;
            int y = Pow(M, e, x);
            
            return y;
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            int x = p * q;
            int y = (p - 1) * (q - 1);
            int z = 1;
            
            for (int i = 1; i < y; i++)
            {
                if (((e % y) * (i % y)) % y == 1)
                {
                    z = i;
                    break;

                }
            }

            int f = Pow(C, z, x);
            return f;
        }
    }
}

