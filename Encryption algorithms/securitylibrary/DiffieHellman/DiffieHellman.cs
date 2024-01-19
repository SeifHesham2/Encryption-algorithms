using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman
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
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            List<int> r = new List<int>();
            int ya = Pow(alpha, xa, q);
            int yb = Pow(alpha, xb, q);
            int k1 = Pow(yb, xa, q);
            int k2 = Pow(ya, xb, q);
            
            r.Add(k1);
            r.Add(k2);

            return r;
        }
    }
}
