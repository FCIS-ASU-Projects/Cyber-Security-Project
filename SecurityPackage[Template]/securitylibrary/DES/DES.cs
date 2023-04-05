using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Data.SqlTypes;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static System.Net.WebRequestMethods;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {

        //initial permutation matrix for input text
        List<int> IP = new List<int>()
        { 
            58,50,42,34,26,18,10,2,
            60,52,44,36,28,20,12,4,
            62,54,46,38,30,22,14,6,
            64,56,48,40,32,24,16,8,
            57,49,41,33,25,17,9,1,
            59,51,43,35,27,19,11,3,
            61,53,45,37,29,21,13,5,
            63,55,47,39,31,23,15,7
        };

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
             14,17,11,24,1,5,
             3,28,15,6,21,10,
             23,19,12,4,26,8,
             16,7,27,20,13,2,
             41,52,31,37,47,55,
             30,40,51,45,33,48,
             44,49,39,56,34,53,
             46,42,50,36,29,32
        };

        List<int> E = new List<int>() 
        {
            32, 1, 2, 3, 4, 5,
            4, 5, 6, 7, 8, 9,
            8, 9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32, 1,
        };

        int[,] S1 = new int[4, 16]
        {
                { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
                { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
                { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
                { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13},
        };

        int[,] S2 = new int[4, 16]
        {
             { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
             { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },
             { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
             { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 },
        };

        int[,] S3 = new int[4, 16]
        {
            { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
            { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
            { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
            { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 },
        };

        int[,] S4 = new int[4, 16]
        {
            { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
            { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
            { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
            { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 },
        };

        int[,] S5 = new int[4, 16]
        {
            { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
            { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
            { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
            { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 },
        };

        int[,] S6 = new int[4, 16]
        {
            { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
            { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
            { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
            { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 },
        };

        int[,] S7 = new int[4, 16]
        {
            { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
            { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },
            { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, },
            { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 },
        };

        int[,] S8 = new int[4, 16]
        {
            { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
            { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
            {  7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
            { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 },
        };

        List<int> P = new List<int>()
        {
            16, 7, 20, 21,
            29, 12, 28, 17,
            1, 15, 23, 26,
            5, 18, 31, 10,
            2, 8, 24, 14,
            32, 27, 3, 9,
            19, 13, 30, 6,
            22, 11, 4, 25,
        };

        List<int> Inv_P = new List<int>()
        {
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25,
        };

        
        public override string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public override string Encrypt(string plainText, string key)
        {
            string cipherText = "";

            // Convert plainText to Binary
            string []binaryText = Text_to_Binary(plainText);
       
            // Iterator on 64-bits (blocks) 
            for (int i = 0; i <  binaryText.Length ; i++)
            {
                // Apply Initial permutation matrix 
                string perm = permutation(binaryText[i], IP);
                
                //Convert Key to Binary
                string[] k = Text_to_Binary(key);
                string[] keys = generate_key(k[i]);

                // Split text(64 bits) to left(32 bits) and right(32 bits)  
                string L = "";
                for (int c = 0; c < 32; c++)
                    L += perm[c];

                string R = "";
                for (int c = 32; c < perm.Length; c++)
                    R += perm[c];

                // LOOP for 16 rounds
                for (int r = 0;  r < 16 ; r++)
                {
                    // save old right
                    string old_R = R;

                    // Expand right (32 bits) to (48 bits)
                    string new_R = expansion(R);

                    // XOR between new_R (48 bits) and key[num Round] (48 bits)
                    new_R = XOR(new_R, keys[r]);

                    // Apply S -boxes, input-> (48 bits) output-> (32 bits)
                    new_R = substition(new_R);
                  
                    //Apply permutation function, output-> (32 bits)
                    new_R = permutation(new_R, P);

                    // new right for next iteration ->  XOR between left (32 bits) and  permutation's output (32 bits)
                    R = XOR(new_R, L );

                    //new left for next iteration
                    L = old_R;                
                }

                // Swap between left and right
                swap(ref L, ref R);
                
                //Inverse Initial permutation (64 bits)
                string cipher = permutation( (L+R) , Inv_P);

                //Convert form Binary to Hex
                cipher = Binary_to_Hex(cipher);
                
                // Concanucate cipherText
                cipherText += cipher;
            }
            return cipherText;
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

         //   Console.WriteLine("C0   " + C0);
           // Console.WriteLine("D0  " + D0);
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
                //Console.WriteLine("CD " + CD);

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

        private string [] Text_to_Binary(string text)
        {
            /*
            get text convert it to binary and breaks it into 64 binary blocks
            Input : input string
            return : list of strings each index in the array contain 64 bit block
            */

            //calc num of blocks
            int num_of_blocks = text.Length / 16;
            if (text.Length % 8 != 0)
                num_of_blocks += 1;

            //padding 0s if text < 64 bits
            if ((text.Length - 2) % 16 != 0)
                 text = text.PadRight((num_of_blocks*16)+2, '0');
             
            
            // Convert to Hex
            List<string> binary = new List<string>();
            string str = "";
            for (int i = 3; i <= text.Length ; i++)
            {
                str += text[i-1];
                if ((i-2) % 16 == 0)
                {
                    binary.Add(Convert.ToString(Convert.ToInt64(str, 16), 2).PadLeft(64, '0'));
                    str = "";
                }
            }

            string [] binaryText = binary.ToArray();
            return binaryText;
        }
        
        private string expansion(string R)
        {
            string new_R = "";

            foreach(var i in E)
                new_R += R[i-1];
        
            return new_R;
        }

        private string XOR(string new_R, string key)
        {
            string ans = "";

            for (int i = 0 ; i < key.Length ;  i++)
            {
                if (new_R[i] == key[i])
                    ans += "0";
                else
                    ans += "1";
            }
        
            return ans;
        }

        private string substition(string op_R)
        {
            string out_s = "";
            int S = 0;  // counter for number of s-box
            string s = ""; 

            for (int i=1 ; i<=op_R.Length ; i++)
            {
                s += op_R[i-1];  // 6 bits

                if ( i % 6 == 0 )
                {
                    S++;

                    //calc Row and Column
                    int row = Convert.ToInt32((s[0].ToString() + s[5].ToString() ), 2);
                    int column = Convert.ToInt32( (s[1].ToString() + s[2].ToString() + s[3].ToString() + s[4].ToString() ), 2);
                    
                    string str = ""; // result of the S-matrix
                    
                    if (S == 1)
                        str = Convert.ToString(S1[row, column], 2).PadLeft(4,'0');
                    else if (S == 2)
                        str = Convert.ToString(S2[row, column], 2).PadLeft(4, '0');
                    else if (S == 3)
                        str = Convert.ToString(S3[row, column], 2).PadLeft(4, '0');
                    else if (S == 4)
                        str = Convert.ToString(S4[row, column], 2).PadLeft(4, '0');
                    else if (S == 5)
                        str = Convert.ToString(S5[row, column], 2).PadLeft(4, '0');
                    else if (S == 6)
                        str = Convert.ToString(S6[row, column], 2).PadLeft(4, '0');
                    else if (S == 7)
                        str = Convert.ToString(S7[row, column], 2).PadLeft(4, '0');
                    else if (S == 8)
                        str = Convert.ToString(S8[row, column], 2).PadLeft(4, '0');

                    out_s +=str;
                    
                    s = "";
                }   
            }
            return out_s;
        }

        private  string Binary_to_Hex(string binary)
        {
            string strHex = Convert.ToInt64(binary, 2).ToString("X");
            return "0x"+strHex;
        }

        private void swap(ref string L, ref string R)
        {
            string temp;
            temp = L;
            L = R;
            R = temp;
        }

    }
}