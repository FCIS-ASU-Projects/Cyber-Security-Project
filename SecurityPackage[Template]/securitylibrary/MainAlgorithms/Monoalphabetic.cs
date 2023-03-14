using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            string key = "";
            cipherText = cipherText.ToLower();
            Dictionary<char, char> characters = new Dictionary<char, char>();
            List<char> letters_plain = new List<char>();
            
            for (char c = 'a'; c <= 'z'; c++)
                characters.Add(c, ' ');

            int j = 0;
            foreach (var i in plainText)
            {
                characters[i] = cipherText[j];
                j++;
            }
           
            for (char c = 'a'; c <= 'z'; c++)
            {
                bool isfound = false;
                for(int i= 0 ; i < cipherText.Length ; i++)
                {
                    if(c == cipherText[i])
                    {
                        isfound = true;
                        break;
                    }
                }
                if(!isfound)
                letters_plain.Add(c);
            }

            j = 0;
            for( char i = 'a' ; i <= 'z' ; i++)
            {
                if (characters[i] == ' ')
                {
                    characters[i] = letters_plain[j];
                    j++;
                }
                key += characters[i];
            }
            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            string plainText = "";

            // Mapping ==> key (A) -> value ( key[0] ) ...
            Dictionary<char, char> characters = new Dictionary<char, char>();

            char c = 'A';
            foreach (var i in key)
            {
                characters[i] = c;
                c++;
            }

            foreach (var i in cipherText)
            {
                var x = characters[i];
                plainText += x;
            }
            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            string cipherText = "";
            // Mapping ==> key (a) -> value ( key[0] ) ...
            Dictionary<char, char> characters = new Dictionary<char, char>();

            char c = 'a';
            foreach (var i in key)
            {
               characters[c] = i;
                c++;
            }

            foreach (var i in plainText)
            {
                var x = characters[i];
                cipherText += x;
            }
            
            return cipherText;
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            cipher = cipher.ToLower();
            string plain = "";

            Dictionary<char, int> characters = new Dictionary<char,int>();
            Dictionary<char, char> sortChar = new Dictionary<char, char>();
            List<char> frq = new List<char>() { 'e', 't', 'a', 'o', 'i', 'n', 's', 'r', 'h', 'l', 'd', 'c', 'u', 'm', 'f', 'p', 'g', 'w', 'y', 'b', 'v', 'k', 'x', 'j', 'q', 'z' };
            
            for (char c = 'a'; c <= 'z'; c++)
                characters.Add(c, 0);

            foreach (var i in cipher)
                characters[i] += 1;

            int j = 0;
            foreach (KeyValuePair<char, int> c in characters.OrderByDescending(key => key.Value))
            {
                sortChar.Add(c.Key, frq[j]);
                j++;
            }

            foreach(var i in cipher)
            {
                var x = sortChar[i];
                plain += x;
            }

            return plain;
        }
    }
}