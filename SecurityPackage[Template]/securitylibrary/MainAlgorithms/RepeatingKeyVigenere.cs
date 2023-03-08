using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        static IDictionary<char, int> lettersTonum = new Dictionary<char, int>()
        { {'a',0}, { 'b', 1 }, { 'c', 2 }, { 'd', 3 },
          { 'e', 4 },{'f',5},{'g',6},{'h',7},{'i',8},{'j',9},
          {'k',10},{'l',11},{'m',12},{'n',13},{'o',14},{'p',15},
          {'q',16},{'r',17},{'s',18},{'t',19},{'u',20},{'v',21},
          {'w',22},{'x',23},{'y',24},{'z',25}};
        public string Analyse(string plainText, string cipherText)
        {
            string key = "";
            int num1 = 0, num2 = 0, numOfletter = 0;
            for (int i = 0; i < cipherText.Length; i++)
            {
                num1 = lettersTonum[Char.ToLower(plainText[i])];
                num2 = lettersTonum[Char.ToLower(cipherText[i])];

                if (num1 != num2)
                    numOfletter = ((num2 + 26) - num1) % 26;
                else
                    numOfletter = 0;
                key += lettersTonum.ElementAt(Math.Abs(numOfletter)).Key;


            }

            int count = 0;
            int k = 0;
            for (int j = 1; j < key.Length; j++)
            {
                if (key[j] == key[k])
                {
                    j++;
                    k++;
                    count++;
                    for (; j < key.Length; j++)
                    {
                        if (key[j] != key[k])
                        {
                            k = 0;
                            count = 0;
                            j--;
                            break;
                        }
                        count++;
                        k++;
                    }
                }



            }

            if (count != 0)
            {
                int eok = key.Length - count;
                key = key.Substring(0, eok);
            }
            Console.WriteLine(count);
            Console.WriteLine(key);

            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            string PT = "";
            int j = 0, num1 = 0, num2 = 0;
            for (int i = 0; i < cipherText.Length; i++)
            {
                int numOfletter = 0;
                if (i >= key.Length)
                {
                    j = i % key.Length;
                    num1 = lettersTonum[Char.ToLower(key[j])];     

                }
                else
                {
                    num1 = lettersTonum[Char.ToLower(key[i])];

                    
                }
                num2 = lettersTonum[Char.ToLower(cipherText[i])];
                if (num1 != num2)
                    numOfletter = ((num2 + 26) - num1) % 26;
                else
                    numOfletter = 0;

                PT += lettersTonum.ElementAt(Math.Abs(numOfletter)).Key.ToString();
                Console.WriteLine((lettersTonum.ElementAt(Math.Abs(numOfletter)).Key).ToString());
            }
            return PT.ToUpper();
        }

        public string Encrypt(string plainText, string key)
        {
            string CT = "";
            string keyStream = generate_keyStream(plainText, key);
            for (int i = 0; i < plainText.Length; i++)
            {
                int numOfletter = lettersTonum[Char.ToLower(plainText[i])] + lettersTonum[Char.ToLower(keyStream[i])];
                //Console.WriteLine(plainText[i] + " "+ keyStream[i]);
                numOfletter = numOfletter % 26;
                CT += (lettersTonum.ElementAt(numOfletter).Key).ToString();
                //Console.WriteLine((lettersTonum.ElementAt(numOfletter).Key).ToString());

            }
            return CT.ToUpper();
        }
        private string generate_keyStream(string plainText,string key)
        {
                string keyStream = key;
           
                int diff = plainText.Length - key.Length;
            

                for(int i=0;i<diff;i+=key.Length)
                {
                    if(key.Length <= diff - i)
                    {
                        keyStream = keyStream + key.Substring(0, key.Length);
                    }
                    else
                    {
                        keyStream = keyStream + key.Substring(0, (diff - i));
                    }
                }
               // keyStream = key + plainText.Substring(0, diff);
            
            return keyStream;
        }
    }
}