using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public static class Extensions
    {
        public static K FindFirstKeyByValue<K, V>(this Dictionary<K, V> dict, V val)
        {
            return dict.FirstOrDefault(entry =>
                EqualityComparer<V>.Default.Equals(entry.Value, val)).Key;
        }
    }

    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {
        Dictionary<char, int> IndexOfChar = new Dictionary<char, int>();

        public int GCD(int num1, int num2)
        {
            int Remainder;

            while (num2 != 0)
            {
                Remainder = num1 % num2;
                num1 = num2;
                num2 = Remainder;
            }

            return num1;
        }
        public void setIndexOfChar()
        {
            IndexOfChar.Add('a', 0);
            IndexOfChar.Add('b', 1);
            IndexOfChar.Add('c', 2);
            IndexOfChar.Add('d', 3);
            IndexOfChar.Add('e', 4);
            IndexOfChar.Add('f', 5);
            IndexOfChar.Add('g', 6);
            IndexOfChar.Add('h', 7);
            IndexOfChar.Add('i', 8);
            IndexOfChar.Add('j', 9);
            IndexOfChar.Add('k', 10);
            IndexOfChar.Add('l', 11);
            IndexOfChar.Add('m', 12);
            IndexOfChar.Add('n', 13);
            IndexOfChar.Add('o', 14);
            IndexOfChar.Add('p', 15);
            IndexOfChar.Add('q', 16);
            IndexOfChar.Add('r', 17);
            IndexOfChar.Add('s', 18);
            IndexOfChar.Add('t', 19);
            IndexOfChar.Add('u', 20);
            IndexOfChar.Add('v', 21);
            IndexOfChar.Add('w', 22);
            IndexOfChar.Add('x', 23);
            IndexOfChar.Add('y', 24);
            IndexOfChar.Add('z', 25);
        }
        public void ConvertStringsToIntLists(string text1, string text2, ref List<int> list1, ref List<int> list2)
        {
            setIndexOfChar();
            text1 = text1.ToLower();
            text2 = text2.ToLower();

            for (int i = 0; i < text1.Length; i++)
                list1.Add(IndexOfChar[text1[i]]);

            for (int i = 0; i < text2.Length; i++)
                list2.Add(IndexOfChar[text2[i]]);
        }
        static IEnumerable<IEnumerable<T>> GetPermutationsWithRept<T>(IEnumerable<T> list, int length)
        {
            if (length == 1) return list.Select(t => new T[] { t });
            return GetPermutationsWithRept(list, length - 1)
                .SelectMany(t => list,
                    (t1, t2) => t1.Concat(new T[] { t2 }));
        }
        

        public List<int> Analyse(List<int> plainText, List<int> cipherText) //Need to return 2By2 key
        {
            //Cipher = Key*Plain
            List<int> keyList = new List<int> { -1, -1, -1, -1 }; //2By2Matrix

            //We will try all the combinations that can be used in the key
            var allCombinations = GetPermutationsWithRept(Enumerable.Range(0, 25), 2).ToList();

            //Find key matrix rows
            for (int i = 0; i < allCombinations.Count(); i++)
            {
                //Try this combination
                var currentCombination = allCombinations[i].ToList();
                int a = currentCombination[0], b = currentCombination[1];

                //Get key matrix
                bool foundKeyFirstRow = true;
                bool foundKeySecondRow = true;
                for (int j=0; j<plainText.Count(); j+=2)
                {
                    if (j + 1 >= plainText.Count())
                    {
                        //x index = 23
                        plainText.Add(23); 
                        cipherText.Add(23);
                    }

                    int item_inCipher = (a * plainText[j] + b * plainText[j+1]) % 26;
                    if(item_inCipher != cipherText[j])
                        foundKeyFirstRow = false;
                    if (item_inCipher != cipherText[j+1])
                        foundKeySecondRow = false;
                }
                if(foundKeyFirstRow)
                {
                    keyList[0] = a;
                    keyList[1] = b;
                }
                if (foundKeySecondRow)
                {
                    keyList[2] = a;
                    keyList[3] = b;
                }
            }
            
            if (keyList.Contains(-1)) //Means that there is at least one row in the key did not get answer
                throw new InvalidAnlysisException();

            return keyList;
        }
        public string Analyse(string plainText, string cipherText) //Need to return 2By2 key
        {
            string keyString = "";
            List<int> plainTextlist = new List<int>();
            List<int> cipherTextList = new List<int>();

            ConvertStringsToIntLists(plainText, cipherText, ref plainTextlist, ref cipherTextList);

            List<int> keyList = Analyse(plainTextlist, cipherTextList);

            for (int i = 0; i < keyList.Count(); i++)
                keyString += IndexOfChar.FindFirstKeyByValue(keyList[i]);

            return keyString;
        }
        public List<List<int>> CreateKey3by3Matrix(List<int> key)
        {
            int keyRowSize = 3;
            List<List<int>> keyMatrix = new List<List<int>>();

            int keyListIndex = 0;
            for (int row = 0; row < keyRowSize; row++)
            {
                List<int> rowList = new List<int>();
                for (int col = 0; col < keyRowSize; col++)
                {
                    if (keyListIndex >= key.Count)
                        rowList.Add(23); //23 is the index of letter x
                    else
                        rowList.Add(key[keyListIndex]);

                    keyListIndex++;
                }
                keyMatrix.Add(rowList);
            }
            return keyMatrix;
        }
        public int CalcDet3by3matrix(List<List<int>> matrix)
        {
            int det = 0, rowSize = 3;

            for(int i=0; i<rowSize; i++)
            {
                int factor = (int)Math.Pow(-1, i) * matrix[0][i]; //a, b, or c
                List<int> miniMatrix = new List<int>();

                for (int row=1; row<rowSize; row++)
                {
                    for(int col=0; col<rowSize; col++)
                    {
                        if (col == i)
                            continue;

                        miniMatrix.Add(matrix[row][col]);
                    }
                }
                det += factor * ((miniMatrix[0] * miniMatrix[3]) - (miniMatrix[1] * miniMatrix[2]));
            }

            return ((det % 26) + 26) % 26;
        }
        public int GetMultiplicativeInverseOf3by3Matrix(int det)
        {
            float a = (26 - det), c;

            for (float i = 1; ; i += 26)
            {
                float division = (i / a);
                if (division % 1 == 0) //Check if it is not fraction
                {
                    c = (i / a);
                    break;
                }
            }

            float b = 26 - c; //MultiplicativeInverseOf3by3Matrix
            
            if (((int)b * det) % 26 != 1)
                throw new System.Exception();

            return (int)b;
        }
        public int GetMulOfMiniMatrix(List<List<int>> Key3By3Matrix, int currentRow, int currentCol)
        {
            int ans = 0, keyRowSize = 3;
            List<int> miniMatrix = new List<int>();

            for (int row = 0; row < keyRowSize; row++)
            {
                for (int col = 0; col < keyRowSize; col++)
                {
                    if (row == currentRow || col == currentCol)
                        continue;
                    miniMatrix.Add(Key3By3Matrix[row][col]);
                }
            }
            ans += ((miniMatrix[0] * miniMatrix[3]) - (miniMatrix[1] * miniMatrix[2]));
            return ans;
        }
        public List<int> getKeyTranspose(List<List<int>> Key3By3Matrix)
        {
            int keyRowSize = 3;
            List<int> keyTranspose = new List<int>();

            for(int row=0; row< keyRowSize; row++)
            {
                for(int col=0; col<keyRowSize; col++)
                    keyTranspose.Add(Key3By3Matrix[col][row]);
            }

            return keyTranspose;
        }
        public List<int> Mul2Matrices(List<int> text, List<int> keyOrInversKey)
        {
            List<int> listAfterMul = new List<int>();
            int keyRowSize = (int)Math.Sqrt(keyOrInversKey.Count);
            List<int> text_i = new List<int>();

            for (int textIndex = 0; textIndex < text.Count(); textIndex += keyRowSize)
            {
                //Fill text of i to be mx1 matrix, such that key matrix = mxm.
                text_i.Clear();
                for (int ii = 0; ii < keyRowSize; ii++)
                {
                    if (textIndex + ii >= text.Count())
                        text_i.Add(23); //23 is the index of letter X
                    else
                        text_i.Add(text[textIndex + ii]);
                }

                //Start calculating the text
                //Each time this loop starts, it creats one col
                for (int row = 0; row < keyOrInversKey.Count(); row += keyRowSize) //Iterate on Row
                {
                    int decOrEncCell = 0;
                    for (int col = 0; col < keyRowSize; col++) //Iterate on Col
                        decOrEncCell += text_i[col] * keyOrInversKey[row + col];

                    listAfterMul.Add(((decOrEncCell % 26) + 26) % 26);
                }
            }

            return listAfterMul;
        }
        public List<int> GetDecryptedList2By2KeyMatrix(List<int> cipherText, List<int> key)
        {
            //Get key Inverse
            float a = key[0], b = key[1], c = key[2], d = key[3];

            float det = (((1 / (a * d - b * c)) % 26) + 26) % 26;
            if (det == 0.0 || GCD((int)det, 26) != 1)
                throw new System.Exception();

            key[0] = (int)(det * d);
            key[1] = (int)(det * -1 * b);
            key[2] = (int)(det * -1 * c);
            key[3] = (int)(det * a);

            //Multiply key by cipherText and return it
            return Mul2Matrices(cipherText, key);
        }
        public List<int> GetDecryptedList3By3KeyMatrix(List<int> cipherText, List<int> key)
        {
            List<List<int>> Key3By3Matrix = CreateKey3by3Matrix(key);
            int det = CalcDet3by3matrix(Key3By3Matrix);
            if (det == 0 || GCD(det, 26) != 1)
                throw new System.Exception();
            int b = GetMultiplicativeInverseOf3by3Matrix(det);

            List<List<int>> keyInverse3by3Matrix = new List<List<int>>();
            int keyRowSize = 3;

            for (int currentRow = 0; currentRow < keyRowSize; currentRow++)
            {
                List<int> currentRowList = new List<int>();

                for (int currentCol = 0; currentCol < keyRowSize; currentCol++)
                {
                    int sign = (int)Math.Pow(-1, (currentRow + currentCol));
                    int ansOfMiniMatrix = GetMulOfMiniMatrix(Key3By3Matrix, currentRow, currentCol);
                    currentRowList.Add((((b * sign * ansOfMiniMatrix) % 26) + 26) % 26);
                }
                keyInverse3by3Matrix.Add(currentRowList);
            }

            List<int> keyTranspose = getKeyTranspose(keyInverse3by3Matrix);

            return Mul2Matrices(cipherText, keyTranspose);
        }
        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            //Chek if all elements in key are nonnegative and less than 26
            for(int i=0; i<key.Count(); i++)
            {
                if(key[i]<0)
                    throw new System.Exception();
            }

            //START DECRYPTING
            int keyRowSize = (int)Math.Sqrt(key.Count);

            //2By2 Matrix
            if (keyRowSize == 2)
                return GetDecryptedList2By2KeyMatrix(cipherText, key);

            //3By3 Matrix
            else // keyRowSize == 3
                return GetDecryptedList3By3KeyMatrix(cipherText, key);
        }
        public string Decrypt(string cipherText, string key)
        {
            string decryptedText = "";
            List<int> cipherTextList = new List<int>();
            List<int> keyList = new List<int>();

            ConvertStringsToIntLists(cipherText, key, ref cipherTextList, ref keyList);

            List<int> decryptedCipherTextList = Decrypt(cipherTextList, keyList);

            for(int i=0; i< decryptedCipherTextList.Count(); i++)
                decryptedText += IndexOfChar.FindFirstKeyByValue(decryptedCipherTextList[i]);

            return decryptedText;
        }
        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            List<int> EncryptedList = Mul2Matrices(plainText, key);

            return EncryptedList;
        }
        public string Encrypt(string plainText, string key)
        {
            string EncryptedText = "";
            List<int> plainTextList = new List<int>();
            List<int> keyList = new List<int>();

            ConvertStringsToIntLists(plainText, key, ref plainTextList, ref keyList);

            List<int> EncryptedTextList = Encrypt(plainTextList, keyList);

            for (int i = 0; i < EncryptedTextList.Count(); i++)
                EncryptedText += IndexOfChar.FindFirstKeyByValue(EncryptedTextList[i]);

            return EncryptedText;
        }
        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            //Cipher = Key*Plain
            List<int> keyList = new List<int> { -1, -1, -1, -1, -1, -1, -1, -1, -1}; //3By3Matrix

            //We will try all the combinations that can be used in the key
            var allCombinations = GetPermutationsWithRept(Enumerable.Range(0, 25), 3).ToList();

            //Find key matrix rows
            for (int i = 0; i < allCombinations.Count(); i++)
            {
                //Try this combination
                var currentCombination = allCombinations[i].ToList();
                int a = currentCombination[0], b = currentCombination[1], c = currentCombination[2];

                //Get key matrix
                bool foundKeyFirstRow = true;
                bool foundKeySecondRow = true;
                bool foundKeyThirdRow = true;
                for (int j=0; j<plain3.Count(); j+=3)
                {
                    if (j + 1 >= plain3.Count())
                    {
                        //x index = 23
                        plain3.Add(23); 
                        cipher3.Add(23);
                    }
                    if (j + 2 >= plain3.Count())
                    {
                        //x index = 23
                        plain3.Add(23); 
                        cipher3.Add(23);
                    }

                    int item_inCipher = (a * plain3[j] + b * plain3[j + 1] + c * plain3[j + 2]) % 26;
                    if(item_inCipher != cipher3[j])
                        foundKeyFirstRow = false;
                    if (item_inCipher != cipher3[j+1])
                        foundKeySecondRow = false;
                    if (item_inCipher != cipher3[j+2])
                        foundKeyThirdRow = false;
                }
                if(foundKeyFirstRow)
                {
                    keyList[0] = a;
                    keyList[1] = b;
                    keyList[2] = c;
                }
                if (foundKeySecondRow)
                {
                    keyList[3] = a;
                    keyList[4] = b;
                    keyList[5] = c;
                }
                if (foundKeyThirdRow)
                {
                    keyList[6] = a;
                    keyList[7] = b;
                    keyList[8] = c;
                }
            }

            if (keyList.Contains(-1)) //Means that there is at least one row in the key did not get answer
                throw new InvalidAnlysisException();

            return keyList;
        }
        public string Analyse3By3Key(string plain3, string cipher3)
        {
            string keyString = "";
            List<int> plainTextlist = new List<int>();
            List<int> cipherTextList = new List<int>();

            ConvertStringsToIntLists(plain3, cipher3, ref plainTextlist, ref cipherTextList);

            List<int> keyList = Analyse(plainTextlist, cipherTextList);

            for (int i = 0; i < keyList.Count(); i++)
                keyString += IndexOfChar.FindFirstKeyByValue(keyList[i]);

            return keyString;
        }
    }
}
