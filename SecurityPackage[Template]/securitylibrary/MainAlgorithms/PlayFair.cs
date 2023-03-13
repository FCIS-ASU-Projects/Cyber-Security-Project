using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        char[,] matrix = new char[5, 5];
        IDictionary<char, int> letters_existance = new Dictionary<char, int>()
        { {'a',0}, { 'b', 0 }, { 'c', 0 }, { 'd', 0 },
          { 'e', 0 },{'f',0},{'g',0},{'h',0},{'i',0},{'j',0},
          {'k',0},{'l',0},{'m',0},{'n',0},{'o',0},{'p',0},
          {'q',0},{'r',0},{'s',0},{'t',0},{'u',0},{'v',0},
          {'w',0},{'x',0},{'y',0},{'z',0}};
        
        IDictionary<char, KeyValuePair<int, int>> letters_position = new Dictionary<char, KeyValuePair<int, int>>();
        public string Decrypt(string cipherText, string key)
        {
            string PT = "";
            
            cipherText = cipherText.ToLower();
            matrix = generate_matrix(key);
            KeyValuePair<int, int> ij1, ij2;

            for (int i = 0; i < cipherText.Length; i += 2)
            {
                char _1st,_2nd;
                ij1 = letters_position[cipherText[i]];
                if (i == cipherText.Length - 1)
                {
                    ij2 = letters_position['x'];
                }
                else if (cipherText[i] == cipherText[i + 1])
                {
                    ij2 = letters_position['x'];
                    i--;
                }
                else
                {
                    ij2 = letters_position[cipherText[i + 1]];
                }

                //ij2 = letters_position[cipherText[i + 1]];
                

                if (ij1.Key == ij2.Key) //same row
                {
                    _1st = matrix[ij1.Key, ((ij1.Value - 1) + 5) % 5];
                    
                   
                    _2nd = matrix[ij2.Key, ((ij2.Value - 1) + 5) % 5];
                   
                }
                else if (ij1.Value == ij2.Value) // same column
                {
                    _1st = matrix[((ij1.Key - 1) + 5) % 5, ij1.Value];
                    
                    _2nd = matrix[((ij2.Key - 1) + 5) % 5, ij2.Value];
                    
                }
                else
                {
                    _1st = matrix[ij1.Key, ij2.Value];
                    
                    _2nd = matrix[ij2.Key, ij1.Value];
                
                }

                PT += _1st;
                PT += _2nd; 


            }
            if (PT[PT.Length -1] == 'x' )
                PT = PT.Remove(PT.Length -1, 1);

            for (int i=0;i<PT.Length;i+=2)
            {
                
                if( i+2 < PT.Length)
                {
                    if ((PT[i+1] == 'x') && (PT[i] == PT[i+2]))
                    {
                        PT = PT.Remove(i+1, 1).Insert(i+1, "");
                        i--;
                        Console.WriteLine(PT);
                    }
                   
                }
              
               




            }

            Console.WriteLine(PT);
            return PT;
        }
        
        public string Encrypt(string plainText, string key)
        {
            string CT = "";
            plainText= plainText.ToLower();
            matrix = generate_matrix(key);
            KeyValuePair<int, int> ij1,ij2;
           
            for(int i=0;i<plainText.Length;i+=2)
            {
                ij1 = letters_position[plainText[i]];
                if(i == plainText.Length -1)
                {
                    ij2 = letters_position['x'];
                }
                else if(plainText[i] == plainText[i+1])
                {
                    ij2 = letters_position['x'];
                    i--;
                }
                else
                {
                    ij2 = letters_position[plainText[i + 1]];
                }
                
                if(ij1.Key == ij2.Key) //same row
                {
                    CT += matrix[ij1.Key , (ij1.Value + 1) % 5];
                    CT += matrix[ij2.Key, (ij2.Value + 1) % 5];
                }
                else if(ij1.Value == ij2.Value) // same column
                {
                    CT += matrix[(ij1.Key +1)%5, ij1.Value];
                    CT += matrix[(ij2.Key + 1) % 5, ij2.Value ];
                }
                else
                {
                    CT += matrix[ij1.Key,ij2.Value];
                    CT += matrix[ij2.Key, ij1.Value];
                }
                
            }
            Console.WriteLine(CT);
            return CT;

        }
        private char[,] generate_matrix(string key)
        {
            int  col = 0, row = 0;
            key = key.ToLower();
            bool ij_cell = false;
            for (int i = 0; i < key.Length; i++)
            {
                if (letters_existance[key[i]] == 0)
                {
                    matrix[row, col] = key[i];
                    
                    if ((key[i] == 'i' || key[i] == 'j' )&& ij_cell==false )
                    {
                        letters_existance['j'] = letters_existance['i'] = 1;
                        letters_position.Add('i', new KeyValuePair<int, int>(row, col));
                        letters_position.Add('j', new KeyValuePair<int, int>(row, col));
                        ij_cell=true;
                        Console.WriteLine(key[i]);
                        Console.WriteLine(row + " " + col);
                    }
                    else
                    {
                        letters_existance[key[i]] = 1;
                        letters_position.Add(key[i], new KeyValuePair<int, int>(row, col));
                        Console.WriteLine(key[i]);
                        Console.WriteLine(row + " " + col);
                    }
                    col++;
                    if (col == 5)
                    {
                        row++;
                        col = 0;
                    }
                    
                }
            }
            if (row == 5 )
                return matrix;
            else 
            {
              
              for(int i=0;i<letters_existance.Count();i++) 
              {
                 char _key = letters_existance.ElementAt(i).Key;
                 int val = letters_existance.ElementAt(i).Value;
                if (val == 0)
                {
                        matrix[row, col] = _key;

                        
                        if ((_key == 'i' || _key == 'j')&& ij_cell == false)
                        {
                            letters_existance['j'] = 1;
                            letters_existance['i'] = 1;
                            letters_position.Add('i', new KeyValuePair<int, int>(row, col));
                            letters_position.Add('j', new KeyValuePair<int, int>(row, col));
                            ij_cell = true;
                            Console.WriteLine(_key);
                            Console.WriteLine(row + " " + col);
                        }
                        else
                        {
                            letters_existance[_key] = 1;
                            letters_position.Add(_key, new KeyValuePair<int, int>(row, col));
                            Console.WriteLine(_key);
                            Console.WriteLine(row +" "+col);
                        }
                        col++;
                       if (col == 5)
                       {
                           row++;
                           col = 0;
                       }
                }
              }
                return matrix;
            }

            
        }
        
    }
}