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
            //throw new NotImplementedException();

            // b^-1 mod m
            //initial values (A1, A2, A3) = (1, 0, m)
            //initial values (B1, B2, B3) = (0, 1, b)

            int A1_Result = 1;
            int A2_Result = 0;
            int A3_Result = baseN;
            int B1_Result = 0;
            int B2_Result = 1;
            int B3_Result = number;

            while(true)
            {
                if (B3_Result == 0) return -1;

                else if (B3_Result == 1)
                {
                    int ans=((B2_Result % baseN) + baseN) % baseN;
                    return ans;
                }

                int Q_Result = A3_Result / B3_Result;

                int T1_Result = (A1_Result - (Q_Result * B1_Result));
                int T2_Result = (A2_Result - (Q_Result * B2_Result));
                int T3_Result = (A3_Result - (Q_Result * B3_Result));

                A1_Result = B1_Result;
                A2_Result = B2_Result;
                A3_Result = B3_Result;

                B1_Result = T1_Result;
                B2_Result = T2_Result;
                B3_Result = T3_Result;
            }
        }
    }
}
