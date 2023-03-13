using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            plainText=plainText.ToLower();
            cipherText=cipherText.ToLower();

            List<int> keyList = new List<int>();
            
            List<List<int>> allPermutations;

            for(int j=1; j<=7; ++j)
            {
                allPermutations = PermutationListOfInt(j);
                for (int i = 0; i < allPermutations.Count; ++i)
                {
                    if (Encrypt(plainText, allPermutations[i]) == cipherText)
                        keyList = allPermutations[i];
                }
            }

            return keyList;
        }
        public List<List<int>> PermutationListOfInt(int countOfNums)
        {
            int[] numsOfKey = new int[countOfNums];

            for (int i = 0; i < countOfNums; ++i)
                numsOfKey[i] = i + 1;

            List<List<int>> listOfPermutations = new List<List<int>>();

            return Permutation(numsOfKey, 0, numsOfKey.Length - 1, listOfPermutations);
        }

        public List<List<int>> Permutation(int[] numsOfKey, int startIndex, int endIndex, List<List<int>> listOfPermutations)
        {
            if (startIndex == endIndex)
                listOfPermutations.Add(new List<int>(numsOfKey));
            else
            {
                for (int i = startIndex; i <= endIndex; ++i)
                {
                    Swap(ref numsOfKey[startIndex], ref numsOfKey[i]);
                    Permutation(numsOfKey, startIndex + 1, endIndex, listOfPermutations);
                    Swap(ref numsOfKey[startIndex], ref numsOfKey[i]);
                }
            }

            return listOfPermutations;
        }

        public void Swap(ref int a, ref int b)
        {
            int temp = a;
            a = b;
            b = temp;
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            int columnsCount = (int)Math.Ceiling((double)cipherText.Length / (double)key.Count);
            List<String> columnsDic = new List<String>();
            List<String> rowsDic = new List<String>();
            String plainText ;

            for (int i = 0; i < cipherText.Length; i+=columnsCount)
            {
                plainText = "";
                for(int j=i; j<columnsCount+i; ++j)
                {
                    if (j < cipherText.Length)
                        plainText += cipherText[j];
                    else plainText += 'X';
                }
                
                columnsDic.Add(plainText);
            }

            for (int i = 0; i <key.Count; ++i)
                rowsDic.Add(columnsDic[key[i] - 1]);

            plainText = "";

            for(int i=0; i<columnsCount; ++i)
            {
                for(int j=0; j < key.Count; ++j)
                    plainText += rowsDic[j][i];
            }

            return plainText;
        }

        public string Encrypt(string plainText, List<int> key)
        {
            String cipherText;
            SortedDictionary<int, String> plainDic = new SortedDictionary<int, String>();

            for (int i = 0; i < key.Count; ++i)
            {
                cipherText = "";

                for (int j = i; j < plainText.Length; j += key.Count)
                    cipherText += plainText[j];

                plainDic[key[i]] = cipherText;
            }

            cipherText = "";

            foreach (var item in plainDic)
                cipherText += item.Value;

            return cipherText;
        }
    }
}

