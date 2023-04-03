using System;
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
        //initial permutation matrix for input text
        List<int> IP = new List<int>() { 58,50,42,34,26,18,10,2,
                                         60,52,44,36,28,20,12,4,
                                         62,54,46,38,30,22,14,6,
                                         64,56,48,40,32,24,16,8,
                                         57,49,41,33,25,17,9,1,
                                         59,51,43,35,27,19,11,3,
                                         61,53,45,37,29,21,13,5,
                                         63,55,47,39,31,23,15,7};
        List<int> PC_1 = new List<int>
        {
            57,49,41,33,25,17,9,
            1,58,50,42,34,26,18,
            10,2,59,51,43,35,27,
            19,11,3,60,52,44,36,
            63,55,47,39,31,23,15,
            7,62,56,46,38,30,22,
            14,6,61,53,45,37,29,
            21,13,5,28,20,12,4
        };
        List<int> PC_2 = new List<int>
        {
             14,14,11,24,1,5,
             3,28,15,6,21,10,
             23,19,12,4,26,8,
             16,7,27,20,13,2,
             41,52,31,37,47,55,
             30,40,51,45,33,48,
             44,49,39,56,34,53,
             46,42,50,36,29,32
        };
        public override string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public override string Encrypt(string plainText, string key)
        {
            //use these linees for test only
            string []tt=Text_to_binary(plainText);
            string perm = permutation(tt[0],IP);
            //Console.WriteLine(perm);
            string[] k = Text_to_binary(key);
            //Console.WriteLine(k.Length);
            generate_key(k[0]);
            return perm ;

        }

        private string[] generate_key(string key)
        {
            /*
             take 64 bit key block ,then apply permutation choic1 >> break 56 bit res into C0,D0 >>
             circular shift left >> concetenate C0,D0 >> permutation ch2 >>save 48 bit res as keys[0]
             then apply this process for 16 times
             
            input:64 bit block
            return: array of string contains 16 key

             */
            string[] keys = new string[16];

           
            //permutation choice 1
            string Perm_ch1 = permutation(key, PC_1); //56 bit block
           // Console.WriteLine(Perm_ch1.Length);
            string C0 = Perm_ch1.Substring(0, 28);
            string D0 = Perm_ch1.Substring(28);

            //Console.WriteLine(C0);
            //Console.WriteLine(D0);
            string Ci=C0, Di=D0;
            for (int i= 1;i<=16;i++)
            {
                
                //circular shift left based on round number
                if(i == 1 || i==2 || i==9 || i==16) 
                {
                  
                   Ci = Ci.Insert(Ci.Length , Ci[0].ToString()).Remove(0,1);
                   Di = Di.Insert(Di.Length, Di[0].ToString()).Remove(0, 1);

                }
                else
                {
                    Ci = Ci.Insert(Ci.Length, Ci.Substring(0, 2)).Remove(0, 2);
                    Di = Di.Insert(Di.Length, Di.Substring(0, 2)).Remove(0, 2);
                }

                string CD = Ci + Di;
                //Console.WriteLine(CD.Length);
                //permutation choice 2
                string Perm_ch2 = permutation(CD, PC_2); //48 bit block
                keys[i - 1] = Perm_ch2;
                //Console.WriteLine(Perm_ch2.Length);

            }
            return keys;
        }

        private string permutation(string bitBlock,List<int> perm_matrix)
        {
            /*
             permute  binary string using specified permutation matrix(ex:IP,PC-1,..)
             input:block of bits , matrix (that we will use it to apply permutation on bits)
             return permutated string
             */
            string permutated = "";
        
            for(int i=0;i< perm_matrix.Count;i++)
            {
                int idx = perm_matrix.ElementAt(i) - 1;
                permutated += bitBlock[idx];

            }
            return permutated;
        }
        private string[] Text_to_binary(string text)
        {
            /*
             get text convert it to binary and breaks it into 64 binary blocks
             Input : input string
             return : array of strings each index in the array contain 64 bit block
             */
            int num_of_blocks = text.Length/8;
            if (text.Length % 8 != 0)
                num_of_blocks += 1;

            string[] binary = new string[num_of_blocks];
         
            UTF8Encoding encoding = new UTF8Encoding();
            byte[] buf = encoding.GetBytes(text);

            StringBuilder binaryStringBuilder = new StringBuilder();
            int i = 1;
    
            foreach (byte b in buf)
            {
                binaryStringBuilder.Append(Convert.ToString(b, 2).PadLeft(8,'0'));
                if(i % 8 == 0)
                {
                    int idx = (i / 8) - 1;
                    binary[idx] = binaryStringBuilder.ToString();
                    
                    binaryStringBuilder = new StringBuilder();
                    //Console.WriteLine(binary[idx]);
                }
                i += 1;
                
            }
     
            //Console.WriteLine(i);
            if(i - 1 % 8 !=0)
            {
                binary[num_of_blocks - 1] = binaryStringBuilder.ToString().PadRight(64, '0');
                //Console.WriteLine(binary[num_of_blocks - 1]);
            }
            
            return binary;
        }
    }
}