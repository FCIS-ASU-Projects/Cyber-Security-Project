using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman
    {
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            //throw new NotImplementedException();
            int ya = power(alpha, xa, q);
            int yb = power(alpha, xb, q);

            List<int> keys = new List<int>();
            int ka = power(yb, xa, q);
            int kb = power(ya, xb, q);
            keys.Add(ka);
            keys.Add(kb);
            return keys;
        }
        public int power(int a, int p, int mod)
        {
            if (p == 0) return 1;
            else if (p == 1) return (a % mod);

            int ret = power(a, p / 2, mod);
            if (p % 2 == 0)
            {
                long res = ((long)ret * (long)ret) % mod;
                return (int)(res);
            }
            else
            {
                long res = ((long)ret * (long)ret * (long)a) % mod;
                return (int)(res);
            }
        }
    }
}
