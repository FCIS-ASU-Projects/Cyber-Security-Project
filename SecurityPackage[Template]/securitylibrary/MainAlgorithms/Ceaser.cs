using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            // Get number ( index of P ) of the character  ==> key (a) -> value (0) ...
            Dictionary<char, int> numbers  =  new Dictionary<char ,int>();
            // Get character  of the number ( index of C ) ==> index (0) -> value (a) ...
            var letters  = new ArrayList();

            char characters = 'a' ;

            //numbers ( a -> 0, b -> 1, c -> 2, ....... )
            //letters ( 0 -> a, 1 -> b, 2 -> c, ....... )
            for (int i=0 ;  i<26 ; i++)
            {
                numbers.Add(characters, i);
                letters.Add(characters);
                characters++;
            }

            string cipherText = "";
            //index of C = (index of P + key) mod 26 
            foreach (var i in plainText)
            {
                int C =  (numbers[i] + key ) % 26;
               var x = letters[C];
                cipherText += x;
            }

            return cipherText;
        }

        public string Decrypt(string cipherText, int key)
        {
            // Get number ( index of P ) of the character  ==> key (A) -> value (0) ...
            Dictionary<char, int> numbers = new Dictionary<char, int>();
            // Get character  of the number ( index of C ) ==> index (0) -> value (A) ...
            var letters = new ArrayList();

            char characters = 'A';

            //numbers ( A -> 0, B -> 1, C -> 2, ....... )
            //letters ( 0 -> A, 1 -> B, 2 -> C, ....... )
            for (int i = 0; i < 26; i++)
            {
                numbers.Add(characters, i);
                letters.Add(characters);
                characters++;
            }

            string plainText = "";

            // index of C + 26
            // index of P = (index of C - key )%26 
            foreach (var i in cipherText)
            {
                numbers[i] += 26;
                int P = (numbers[i] - key) %26;
                var x = letters[P];
                plainText += x;
            }
            return plainText;
        }

        public int Analyse(string plainText, string cipherText)
        {
            cipherText =  cipherText.ToLower();
            int key = 0;

            if (plainText == cipherText)
                return key;

            // Get number ( index of P ) of the character  ==> key (a) -> value (0) ...
            Dictionary<char, int> numbers = new Dictionary<char, int>();
            // Get character  of the number ( index of C ) ==> index (0) -> value (a) ...
            var letters = new ArrayList();

            char characters = 'a';

            //numbers ( a -> 0, b -> 1, c -> 2, ....... )
            //letters ( 0 -> a, 1 -> b, 2 -> c, ....... )
            for (int i = 0; i < 26; i++)
            {
                numbers.Add(characters, i);
                letters.Add(characters);
                characters++;
            }

            // index of P < index of C ==> key = P - C
            // index of P > index of C ==> key = (C+26) - P
            for (int i = 0; i < plainText.Length; i++)
            {
                if (numbers[plainText[i]] < numbers[cipherText[i]])
                    key = numbers[plainText[i]] - numbers[cipherText[i]];
                else
                    numbers[cipherText[i]] += 26;
                    key =  numbers[cipherText[i]]  - numbers[plainText[i]];
            }
            return key;
        }
    }
}