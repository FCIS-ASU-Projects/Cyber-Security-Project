using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            plainText=plainText.ToLower();
            cipherText=cipherText.ToLower();

            int keyDepth = 1;

            for(int i=keyDepth; i<plainText.Length; ++i)
                if (Encrypt(plainText, i).ToLower() == cipherText) keyDepth = i;

            return keyDepth;
        }

        public string Decrypt(string cipherText, int key)
        {
            int numOfColmns = (int)Math.Ceiling((double)cipherText.Length / (double)key);
            String plaintext = "";

            for (int i = 0; i < numOfColmns; ++i)
            {
                for (int j = i; j < cipherText.Length; j+=numOfColmns)
                    plaintext += cipherText[j];
            }

            return plaintext;
        }

        public string Encrypt(string plainText, int key)
        {
            String cipherText="";
            List<List<char>> cipherList=new List<List<char>>();

            for(int i=0; i<key; ++i)
            {
                cipherList.Add(new List<char>());
                for(int j=i; j<plainText.Length; j+=key)
                    cipherList[i].Add(plainText[j]);
            }

            for(int i=0; i<cipherList.Count; ++i)
            {
                for(int j=0; j < cipherList[i].Count; ++j)
                    cipherText += cipherList[i][j];
            }

            return cipherText;
        }
    }
}
