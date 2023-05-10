using SecurityLibrary.AES;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Encrypt(int p, int q, int M, int e)
        {
            //throw new NotImplementedException();
            int n = p * q;
            int c = power(M,e,n);
            return c;
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            //throw new NotImplementedException();
            int n = p * q;
            int phi = (p - 1) * (q - 1);
            // To get mod inverse
            ExtendedEuclid mod = new ExtendedEuclid();
            int mulInv = mod.GetMultiplicativeInverse(e, phi);
            int result = power(C, mulInv, n);
            return result;
         }
        
        public int power(int a, int p,int mod)
        {
            if (p == 0) return 1;
            else if (p == 1) return (a%mod);

            int ret = power(a, p / 2,mod);
            if (p % 2 == 0)
            {
                long res= ((long)ret * (long)ret) % mod;
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

