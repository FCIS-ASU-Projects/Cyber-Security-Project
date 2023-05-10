using SecurityLibrary.AES;
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
        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            //throw new NotImplementedException();
            //int yb = power(alpha, y, q);
            int K = power(y, k, q);
            long c1 = power(alpha, k, q);
            long c2 =( K * m) % q;
            List<long> list = new List<long>();
            list.Add(c1);
            list.Add(c2);
            return list;
        }
        public int Decrypt(int c1, int c2, int x, int q)
        {
            //throw new NotImplementedException();
            int K = power(c1, x, q);
            ExtendedEuclid extendedEuclid = new ExtendedEuclid();
            int kInverse = extendedEuclid.GetMultiplicativeInverse(K,q);
            int M = (c2 * kInverse) % q;
            return M;
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

