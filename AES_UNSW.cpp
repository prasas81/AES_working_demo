// AES_UNSW.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <iostream>
#include <string>
#include <sstream>
#include <iterator>
#include <vector>
#include <xstring>
#include <array>

#define BLOCK_SIZE 16
#define KEY_SIZE 16
#define WORD_SIZE 4
#define ROW_SIZE 4
#define COL_SIZE 4


/**
 *  xtime macro: (input * {02}) mod {1b}  GF(2^8)
 *  02 = x = 00000010(binary) over GF(2^8)
 *  1b = x^8 + x^4 + x^3 + x^1 + 1 = 00011011(binary) over GF(2^8)
 *
 *
 *  (x << 1) -- input * {02}  = shift 1 bit
 * (x >> 7) - input / 2^7, which means that only the 8th bit is taken
 *  ((x >> 7) & 1) * 0x1b ----
 * If the 8th bit is 1, it means mod(2^7) will be left => 00011011, and finally the entire xtime(x) becomes (x << 1) xor 00011011 (see GF(2^n) quick mod for details Way of calculation)
 * If the 8th bit is 0, it will become 0 * 0x1b, and finally the entire xtime(x) (x << 1) XOR 0 = (x << 1)
 */
//#define xtime(x) ((x << 1) ^ (((x >> 7) & 0x01) * 0x1b))


// Substitution table
const unsigned char s_box[16][16] = {
{ 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
  0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76 },
{ 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
  0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0 },
{ 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
  0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15 },
{ 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
  0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75 },
{ 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
  0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84 },
{ 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
  0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf },
{ 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
  0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8 },
{ 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
  0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2 },
{ 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
  0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73 },
{ 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
  0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb },
{ 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
  0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79 },
{ 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
  0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08 },
{ 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
  0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a },
{ 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
  0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e },
{ 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
  0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf },
{ 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
  0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 },
};

// Inverse substitution table
const unsigned char inv_s_box[16][16] = {
{ 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
  0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb },
{ 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
  0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb },
{ 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
  0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e },
{ 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
  0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25 },
{ 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
  0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92 },
{ 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
  0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84 },
{ 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
  0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06 },
{ 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
  0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b },
{ 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
  0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73 },
{ 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
  0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e },
{ 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
  0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b },
{ 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
  0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4 },
{ 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
  0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f },
{ 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
  0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef },
{ 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
  0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61 },
{ 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
  0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d },
};

// Returns a string object that contains hexadecimal value of the input string.
std::string HexConvert(std::string &str_obj)
{  
    
    std::string hex_value;
    char const hex_chars[16] = { '0', '1', '2', '3', '4', '5', '6', '7', \
                                 '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

    for (auto& byte : str_obj) {
        // Mask the lower 4 bits of input byte with 0xF0 and right 
        // shift 4 times so that higer 4 bits are now located in 
        // the lower 4 bits

        hex_value += hex_chars[(byte & 0xF0) >> 4];
        // Mask the higher 4 bits of the input byte with 0x0F and 
        // extact the lower for bits
        hex_value += hex_chars[(byte & 0x0F) >> 0];
    }

    return hex_value;
}


// Rotate the word to the of the input matrix column
// 1st byte is replaced with the 2nd byte, 
// 2nd byte is replaced with 3rd byte,
// 3rd byte is replaced with 4th byte,
// 4th byte is replaced with 1st byte.
void RotateWord(unsigned char* column_word) {
    unsigned char temp;
    temp = column_word[0];
    column_word[0] = column_word[1];
    column_word[1] = column_word[2];
    column_word[2] = column_word[3];
    column_word[3] = temp;
 }


// Substitute a given byte by masking the lower 4 bits of input 
// and shifting it 4 times to the right and mapping with sbox ROW number
// Similarly mask the higher 4 bits of the input byte with 0x0f and 
// mapping it on to sboxColumn number
void SubstituteWord(unsigned char* input_byte) {
    for (int i = 0; i < COL_SIZE; i++) {
        input_byte[i] = s_box[(input_byte[i] & 0xF0) >> 4]
                             [input_byte[i] & 0x0F];
    }
}


// This function pretty prints the given matrix.
// 
void PrintMatrix(unsigned char ary[][4], int ColumnSize, \
                 int RowSize, std::string message_to_display)
{
    size_t message_to_display_size = message_to_display.size();
    std::cout << std::string(message_to_display_size, '-') << std::endl;
    std::cout << message_to_display << std::endl;
    std::cout << std::string(message_to_display_size, '-') << std::endl;
    for (int i = 0; i < RowSize; i++) {
        for (int j = 0; j < ColumnSize; j++) {
            std::string print_character(1, ary[i][j]);
            std::cout << HexConvert(print_character) << " ";
        }
        std::cout << std::endl;
    }
    std::cout << std::endl;
}

// This function calculates KeySchedule and populates word_matrix
// number of rounds is key's size + 6  therefore for 128 bit key its 128-bit key
// and each round needs 16 bytes of keying + one extra key permutation at the very end
// so the key schedule is of 176 bytes long which is stored in 44 x 4 matrix.
// In 176 bytes includes 16 byte input + 160 bytes that are computed 4 at a time.

// W[0]         W[i]  W[i-1]                                W[44]
//  |             |     |                                     |
//  V             V     V                                     V
//  +---------------+------------------+        +---------------+
//  | 1 | 2 | 3 | 3 |   4  | 1 | 2 | 3 |        | 1 | 1 | 2 | 3 |
//  +----------------------------------+        +---------------+
//  | 5 | 6 | 7 | 7 |   7  | 5 | 6 | 7 |        | 5 | 5 | 6 | 7 |
//  +----------------------------------+- - - - +---------------+
//  | 7 | 6 | 6 | 6 |   7  | 7 | 6 | 6 |        | 7 | 7 | 6 | 6 |
//  +----------------------------------+        +---------------+
//  | 6 | 7 | 8 | 8 |   9  | 6 | 7 | 8 |        | 6 | 6 | 7 | 8 |
//  +---------------+------------------+        +---------------+
//  
void BuildKeySchedule(unsigned char word_matrix[][4], std::string &key) {
    unsigned char rcon = 0x01;
    std::memcpy(word_matrix, key.c_str(), key.size());

    PrintMatrix(word_matrix, 4, 4, "Input Key in Hex");
    //key size in 4 byte word
    int key_word = KEY_SIZE >> 2;
    // key word size + 1 extra permutation times key word size
    for (int i = key_word; i < (4 * (key_word + 7)); i++) {
        std::memcpy(word_matrix[i], word_matrix[i - 1], WORD_SIZE);
        if (!(i % key_word))
        {
            RotateWord(word_matrix[i]);
            SubstituteWord(word_matrix[i]);
            if( !(i % 36)) { 
                rcon = 0x1B; 
            }
            word_matrix[i][0] ^= rcon;
            rcon <<= 1;
        }
        word_matrix[i][0] ^= word_matrix[i - key_word][0];
        word_matrix[i][1] ^= word_matrix[i - key_word][1];
        word_matrix[i][2] ^= word_matrix[i - key_word][2];
        word_matrix[i][3] ^= word_matrix[i - key_word][3];
    }
}

// This function XORs state matrix 4 bytes with previous 4 bytes.
void AddRoundKey(unsigned char state_matrix[][4], 
                 unsigned char word_matrix[][4]){
    for (int i = 0; i < COL_SIZE; i++) {
        for (int j = 0; j < ROW_SIZE; j++) {
            state_matrix[j][i] = state_matrix[j][i] ^ word_matrix[i][j];
        }
    }
}

// For each byte in matrix column substitute respective byte by masking 
// the lower 4 bits of input and shifting it 4 times to the right and 
// mapping with sbox ROW number, similarly mask the higher 4 bits of 
// the input byte with 0x0f and mapping it on to s_box Column number.
void SubstituteByte(unsigned char state_matrix[][4]){
    for (int i = 0; i < ROW_SIZE; i++) {
        for (int j = 0; j < COL_SIZE; j++) {
            state_matrix[i][j] = s_box[(state_matrix[i][j] & 0xF0) >> 4]
                                      [state_matrix[i][j] & 0x0F];
        }
    }
}

// For each byte in matrix column substitute respective byte by masking 
// the lower 4 bits of input and shifting it 4 times to the right and 
// mapping with sbox ROW number, similarly mask the higher 4 bits of 
// the input byte with 0x0f and mapping it on to inverse s_box Column number.
void InverseSubstituteByte(unsigned char state_matrix[][4]) {
    for (int i = 0; i < ROW_SIZE; i++) {
        for (int j = 0; j < COL_SIZE; j++) {
            state_matrix[i][j] = inv_s_box[(state_matrix[i][j] & 0xF0) >> 4]
                                          [state_matrix[i][j] & 0x0F];
        }
    }
}

// This function shifts the rows in following order
// 1st row rotated right by 0 bytes.
// 2nd row rotates right by 1 byte.
// 3rd row rotated right by 2 bytes.
// 4th row rotated right by 3 bytes.
void ShiftRows(unsigned char state_matrix[][4]) {
 /*    
* Unaltered State matrix
*        +-------------------+
*        | d4 | e0 | b8 | le |
*        +--------------------
*        | 27 | bf | b4 | 41 |
*        +--------------------
*        | 11 | 98 | 5d | 52 |
*        +--------------------
*        | ae | f1 | e5 | 30 |
*        +-------------------+
*/
int temp_save;
/*
* Rotate First row 1 byte
*        +-------------------+
*        | d4 | e0 | b8 | le |
*        +--------------------
*        | bf | b4 | 41 | 27 |<--
*        +--------------------
*        | 11 | 98 | 5d | 52 |
*        +--------------------
*        | ae | f1 | e5 | 30 |
*        +-------------------+
*/
temp_save = state_matrix[1][0];
state_matrix[1][0] = state_matrix[1][1];
state_matrix[1][1] = state_matrix[1][2];
state_matrix[1][2] = state_matrix[1][3];
state_matrix[1][3] = temp_save;

/*
* Rotate Second row 2 bytes
        +-------------------+
        | d4 | e0 | b8 | le |
        +--------------------
        | bf | b4 | 41 | 27 |
        +--------------------
        | 5d | 52 | 11 | 98 |<--
        +--------------------
        | ae | f1 | e5 | 30 |
        +-------------------+
*/
temp_save = state_matrix[2][0];
state_matrix[2][0] = state_matrix[2][2];
state_matrix[2][2] = temp_save;
temp_save = state_matrix[2][1];
state_matrix[2][1] = state_matrix[2][3];
state_matrix[2][3] = temp_save;

/* Rotate Third row 3 bytes
        +-------------------+
        | d4 | e0 | b8 | le |
        +--------------------
        | bf | b4 | 41 | 27 |
        +--------------------
        | 5d | 52 | 11 | 98 |
        +--------------------
        | 30 | ae | f1 | e5 |<--
        +-------------------+
*/
temp_save = state_matrix[3][3];
state_matrix[3][3] = state_matrix[3][2];
state_matrix[3][2] = state_matrix[3][1];
state_matrix[3][1] = state_matrix[3][0];
state_matrix[3][0] = temp_save;
}

// This function shifts the rows in following order
// 1st row rotated left by 0 bytes.
// 2nd row rotates left by 1 byte.
// 3rd row rotated left by 2 bytes.
// 4th row rotated left by 3 bytes.
void InverseShiftRows(unsigned char state_matrix[][4]) {
 /*
 * Unaltered State matrix
      +-------------------+
      | d4 | e0 | b8 | le |
      +--------------------
      | bf | b4 | 41 | 27 |
      +--------------------
      | 5d | 52 | 11 | 98 |
      +--------------------
      | 30 | ae | f1 | e5 |
      +-------------------+
 */
  int temp_save;
 /*
 * Rotate First row 1 byte
      +-------------------+
      | d4 | e0 | b8 | le |
      +--------------------
   -->| 27 | bf | b4 | 41 | 
      +--------------------
      | 5d | 52 | 11 | 98 |
      +--------------------
      | 30 | ae | f1 | e5 |
      +-------------------+
 */
 temp_save = state_matrix[1][3];
 state_matrix[1][3] = state_matrix[1][2];
 state_matrix[1][2] = state_matrix[1][1];
 state_matrix[1][1] = state_matrix[1][0];
 state_matrix[1][0] = temp_save;

 /*
 * Rotate Second row 2 bytes
      +-------------------+
      | d4 | e0 | b8 | le |
      +--------------------
      | 27 | bf | b4 | 41 |
      +--------------------
  --> | 11 | 98 | 5d | 52 |
      +--------------------
      | 30 | ae | f1 | e5 |
      +-------------------+
 */
 temp_save = state_matrix[2][0];
 state_matrix[2][0] = state_matrix[2][2];
 state_matrix[2][2] = temp_save;
 temp_save = state_matrix[2][1];
 state_matrix[2][1] = state_matrix[2][3];
 state_matrix[2][3] = temp_save;

 /* Rotate Third row 3 bytes
    +-------------------+
    | d4 | e0 | b8 | le |
    +--------------------
    | 27 | bf | b4 | 41 |
    +--------------------
    | 11 | 98 | 5d | 52 |
    +--------------------
 -->| ae | f1 | e5 | 30 |
    +-------------------+
 */
 temp_save = state_matrix[3][0];
 state_matrix[3][0] = state_matrix[3][1];
 state_matrix[3][1] = state_matrix[3][2];
 state_matrix[3][2] = state_matrix[3][3];
 state_matrix[3][3] = temp_save;
}


// This function returns 0x1b if high bit of given byte is 1
// other wise returns 0 this is used in galois field multiplication.
// example: (d4 * 2 ) is d4 << 1 = 1A8 since the high bit of d4 
// is set its XORed with 0x1b which gives b3
// 0xob is dervived from GF(2^8) field and it 
// is represented in irreducible polynomial as x^8+x^4+x^3+x^1+x^0 
// which is inturn represented as 0001 1011 <=> 0x1B in hex
unsigned char xtime(unsigned char x)
{
    return (x << 1) ^ ((x & 0x80) ? 0x1b : 0x00);
}


// This function performs dot product of two variables by Xoring
// Xtime values of multiplicand with the multipler.
unsigned char dot(unsigned char x, unsigned char y)
{
    unsigned char mask;
    unsigned char product = 0;

    for (mask = 0x01; mask; mask <<= 1)
    {
        if (y & mask)
        {
            product ^= x;
        }
        x = xtime(x);
    }

    return product;
}

// This function does Columnn-mixing operation by performing
// linear transformation on each columns by multiplying in to a fixed 
// constants. Since each column has 4 rows
// the matrix transformation has to be 4x4 and is defined as follows
//     | 2  3  1  1 |
// M = | 1  2  3  1 | 
//     | 1  1  2  3 |  
//     | 3  1  1  2 |
// Multiplying by 1 is straight forward
// Multiplying by 2 is equivalent to shifting the number left by one, 
// and then exclusiving-or'ing the value 0x1B if the high bit had been one
// (carry over). If the high bit was zero then there was no need to XOR
// Multiplying 3 can be done mutiplying by 2 and then XORing with orginal value.
// 3 can be written as 2 + 1 <=> 2 XOR 1
// 3 * some_number = (2 XOR 1) * some_number = (2 * some_number) XOR some_number.  
// Once you've multiplied all the vector elements, then you need to add them.
// This "addition" operation is actually XOR operation. 
// They've written it as + because, in GF(2^n) fields, XOR is addition operation.
// if the column [d4 bf 5d 30] needs to be multipled with galios matrix it is
// ( d4 * 0 2) + ( bf * 03 ) + ( 5d * 01 ) + (30 * 01 )
// d4?02  is d4 << 1 and XORed with 0x1B as their is a carry over (high bit of d4 is set)
// which gives the result b3.
// Similiarly, 0xbf x 03 is 0xbf << 1 and XORed with 0x1B resulting in 0xda
// 5d * 01 = 5d
// 30 * 01 = 30
// ( d4 * 0 2) + ( bf * 03 ) + ( 5d * 01 ) + (30 * 01 ) = b3 + da + 5d + 30 = 04
// please note: +  here indicates XOR
//Implementation from Josha Davis book "Implemnting SSL/TLS"
static void MixColumns(unsigned char s[][4])
{
    int c;
    unsigned char t[4];

    for (c = 0; c < 4; c++)
    {
        t[0] = dot(2, s[0][c]) ^ dot(3, s[1][c]) ^ s[2][c] ^ s[3][c];
        t[1] = s[0][c] ^ dot(2, s[1][c]) ^ dot(3, s[2][c]) ^ s[3][c];
        t[2] = s[0][c] ^ s[1][c] ^ dot(2, s[2][c]) ^ dot(3, s[3][c]);
        t[3] = dot(3, s[0][c]) ^ s[1][c] ^ s[2][c] ^ dot(2, s[3][c]);
        s[0][c] = t[0];
        s[1][c] = t[1];
        s[2][c] = t[2];
        s[3][c] = t[3];
    }
}


// This function does Columnn-mixing operation by performing
// linear transformation on each columns by multiplying in to a fixed 
// constants. Since linear transformation has an inverse, this operation
// is invertible. Each column has 4 rows the matrix transformation 
// has to be 4x4 and is defined as follows
//             | 14  11  13  09 |
// Inverse(M) =| 09  14  11  13 | 
//             | 13  09  14  11 |  
//             | 11  13  09  14 |
static void InverseMixColumns(unsigned char s[][4])
{
    int c;
    unsigned char t[4];

    for (c = 0; c < 4; c++)
    {
        t[0] = dot(0x0e, s[0][c]) ^ dot(0x0b, s[1][c]) ^ dot(0x0d, s[2][c]) ^ dot(0x09, s[3][c]);
        t[1] = dot(0x09, s[0][c]) ^ dot(0x0e, s[1][c]) ^ dot(0x0b, s[2][c]) ^ dot(0x0d, s[3][c]);
        t[2] = dot(0x0d, s[0][c]) ^ dot(0x09, s[1][c]) ^ dot(0x0e, s[2][c]) ^ dot(0x0b, s[3][c]);
        t[3] = dot(0x0b, s[0][c]) ^ dot(0x0d, s[1][c]) ^ dot(0x09, s[2][c]) ^ dot(0x0e, s[3][c]);
        s[0][c] = t[0];
        s[1][c] = t[1];
        s[2][c] = t[2];
        s[3][c] = t[3];
    }
}


//This function encrypts the input string with input cipher key
std::string Encrypt(std::string &input, std::string &key) {
    unsigned char state_matrix[4][4];
    // for 128bit key 10 rounds required.
    const int number_rounds = 10;
    // Array to store Key schedule for 128 bit keys
    unsigned char word_matrix[60][4];

    for (int i = 0; i < ROW_SIZE; i++) {
        for (int j = 0; j < COL_SIZE; j++) {
            state_matrix[i][j] = input[i + (4 * j)];
        }
    }

    PrintMatrix(state_matrix, 4, 4, "Input Message in Hex");
    BuildKeySchedule(word_matrix, key);
    PrintMatrix(word_matrix, 44, 4, "Key Schedule Matrix");
    AddRoundKey(state_matrix, &word_matrix[0]);

    for (int round = 0; round < number_rounds; round++)
    {
        SubstituteByte(state_matrix);
        ShiftRows(state_matrix);
        if (round < number_rounds - 1) {
            MixColumns(state_matrix);
        }
        AddRoundKey(state_matrix, &word_matrix[(round + 1) * 4]);
 
    }

    std::string encrypted_char(16,' ');
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            encrypted_char[i+(4*j)] = state_matrix[i][j];
        }
    }

    PrintMatrix(state_matrix, 4, 4, "Encrypted Message Matrix");
    std::cout << "Encrypted message string = "<< encrypted_char << std::endl;
    return encrypted_char;
}

//This function decrypts the input string with input cipher key
std::string Decrypt(std::string& output, std::string& key){
    unsigned char state_matrix[4][4];
    // for 128bit key 10 rounds required.
    const int number_rounds = 10;
    // Array to store Key schedule for 128 bit keys
    unsigned char word_matrix[44][4];
    std::string decrypt_output(16,' ');

    for (int i = 0; i < ROW_SIZE; i++){
        for(int j=0; j< COL_SIZE; j++){
            state_matrix[i][j] = output[i + (4*j)];
        }
    }

    BuildKeySchedule(word_matrix, key);
    AddRoundKey(state_matrix, &word_matrix[number_rounds * 4]);

    for (int round = number_rounds; round > 0; round--)
    {
        InverseSubstituteByte(state_matrix);
        InverseShiftRows(state_matrix);
        AddRoundKey(state_matrix, &word_matrix[(round + 1) * 4]);
        if (round > 1) {
            InverseMixColumns(state_matrix);
        }
    }

    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            decrypt_output += state_matrix[i][j];
        }
    }

    return HexConvert(decrypt_output);
}


int main()
{
    std::string sample_message("MY AES TOOL DEMO");
    std::string init_vector("UNSW_INIT_VECTOR");
    std::string key("UNSW_PROJECT_AES");


    std::cout << "-------------------------" << std::endl;
    std::cout << "Encrypted Output:" << std::endl;
    std::cout << "-------------------------" << std::endl << std::endl;
    std::string encrypted_hex_string = Encrypt(sample_message, key);
    std::cout << "------------------" << std::endl;
    std::cout << "Decrypted Output :" << std::endl;
    std::cout << "------------------" << std::endl;
    std::string decrypted_hex_string = Decrypt(encrypted_hex_string, key);
    std::cout << "In ASCII characters:" << sample_message <<std::endl;
    std::cout << std::endl<<std::endl;
    std::cout << "--------------------";

}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
