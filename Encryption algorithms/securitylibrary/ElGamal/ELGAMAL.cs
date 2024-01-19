using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>

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

        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            int x = Pow(y, k, q);
            long k1 = (long)Pow(alpha, k, q);
            long k2 = ((long)x * (long)m) % q;
            
            List<long> r = new List<long>();
            r.Add(k1);
            r.Add(k2);

            return r;
        }
        public int Decrypt(int c1, int c2, int x, int q)
        {
            // Calculate the shared secret key
            int s = 1;

            for (int i = 0; i < x; i++)
                s = (s * c1) % q;

            int z = Pow(s, q - 2, q);
            int m = (c2 * z) % q;

            return m;
        }
    }
}
