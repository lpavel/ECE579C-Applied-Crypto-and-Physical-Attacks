### This is a template file for a simple AES function.
##
##  Please implement the provided functions and assure that your code
##  works correctly for the example given below
##
##  Name: Laurentiu Pavel
##  Date: 1/29/2015
##

# Rijndael S-box
sbox = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67,
        0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59,
        0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7,
        0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1,
        0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05,
        0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83,
        0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29,
        0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
        0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa,
        0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c,
        0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc,
        0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
        0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19,
        0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee,
        0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
        0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4,
        0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6,
        0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70,
        0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9,
        0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e,
        0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1,
        0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0,
        0x54, 0xbb, 0x16]

iSbox =[0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
        0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
        0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
        0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
        0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
        0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
        0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
        0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
        0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
        0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
        0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
        0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
        0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
        0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
        0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
        0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
        0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d]

Rcon = [0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
        0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
        0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
        0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d,
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab,
        0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d,
        0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25,
        0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01,
        0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
        0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa,
        0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a,
        0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02,
        0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
        0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
        0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
        0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
        0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f,
        0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5,
        0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33,
        0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb ]

# returns the equivalent of the matrix position into a list
def lInd(i,j):
    return i*Nb + j

#next 2 functions are for printing:
def p_state(state):
    for i in range(Nb):
        print(str(hex(state[lInd(i,0)])[2:]) + str(hex(state[lInd(i,1)])[2:]) +
              str(hex(state[lInd(i,2)])[2:]) + str(hex(state[lInd(i,3)])[2:]))

def p_roundKeyValue(roundKeys, r):
    print('Round Key Value')
    for i in range(Nb):
        print(str(hex(roundKeys[lInd(lInd(r,i), 0)])[2:]) +
              str(hex(roundKeys[lInd(lInd(r,i), 1)])[2:]) +
              str(hex(roundKeys[lInd(lInd(r,i), 2)])[2:]) +
              str(hex(roundKeys[lInd(lInd(r,i), 3)])[2:]))
        
    
def addRoundKey(state, roundKeys, r):
    """Adds (XORs) the round key to the state."""
    
    # put your code here
    for i in range(Nb):
        for j in range(Nb):
            state[lInd(j,i)] ^= roundKeys[lInd(lInd(r,i), j)]
    return state

def subBytes(state):
    """Performs SubBytes operation on the state."""

    # put your code here
    for i in range(Nb * Nb):
        state[i] = sbox[state[i]]
    return state

def rotateWord(word, pos):
    """Performs the rotation of a word by a specified number of positions"""
    return word[pos:] + word[0:pos]

def transpose(state):
    """Transposes a matrix. Done because the plaintext decryption comes
        exactly the oposite than how the operations need to be made."""
    newState = []
    for i in range(Nb):
        for j in range(Nb):
            newState.append(state[lInd(j,i)])
    return newState
    
def shiftRows(state):
    """Performs shiftRows operation on the state."""
    # put your code here
    for i in range(Nb):
        state[i*4:i*4+4] = rotateWord(state[i*4:i*4+4], i)
    return state

def gMult(a, b):
    """Multiplication in GF(2^8) - taken form wikipedia
        and adapted to python from C#
        http://en.wikipedia.org/wiki/Rijndael_mix_columns"""
    p = 0
    for i in range(8):
        if b & 1 is not 0:
            p ^= a
        hiBitSet = a & 0x80
        a <<= 1
        if hiBitSet == 0x80:
            a ^= 0x1b
        b >>= 1
    return p % 256

def mixColumns(state):
    """Performs mixColumns operation on the state.
    Again inspired from wikipedia code in C#
    http://en.wikipedia.org/wiki/Rijndael_mix_columns"""

    # put your code here
    for c in range(Nb):
        s0c = state[lInd(0,c)]
        s1c = state[lInd(1,c)]
        s2c = state[lInd(2,c)]
        s3c = state[lInd(3,c)]
        
        state[lInd(0,c)] = gMult(0x02, s0c) ^ gMult(0x03, s1c) ^ s2c ^ s3c
        state[lInd(1,c)] = s0c ^ gMult(0x02, s1c) ^ gMult(0x03, s2c) ^ s3c
        state[lInd(2,c)] = s0c ^ s1c ^ gMult(0x02, s2c) ^ gMult(0x03, s3c)
        state[lInd(3,c)] = gMult(0x03, s0c) ^ s1c ^ s2c ^ gMult(0x02, s3c)
    return state

def iSubBytes(state):
    """Performs inverse SubBytes operation on the state."""

    # put your code here
    for i in range(Nb * Nb):
        state[i] = iSbox[state[i]]
    return state      

def iShiftRows(state):
    """Performs inverse shiftRows operation on the state."""

    # put your code here
    for i in range(Nb):
        state[i*4:i*4+4] = rotateWord(state[i*4:i*4+4], -i)
    return state

def iMixColumns(state):
    """Performs inverse mixColumns operation on the state."""

    # put your code here
    for c in range(Nb):
        s0c = state[lInd(0,c)]
        s1c = state[lInd(1,c)]
        s2c = state[lInd(2,c)]
        s3c = state[lInd(3,c)]
        
        state[lInd(0,c)] = gMult(0x0e, s0c) ^ gMult(0x0b, s1c) ^ \
            gMult(0x0d, s2c) ^ gMult(0x09, s3c)
        state[lInd(1,c)] = gMult(0x09, s0c) ^ gMult(0x0e, s1c) ^ \
            gMult(0x0b, s2c) ^ gMult(0x0d, s3c)
        state[lInd(2,c)] = gMult(0x0d, s0c) ^ gMult(0x09, s1c) ^ \
            gMult(0x0e, s2c) ^ gMult(0x0b, s3c)
        state[lInd(3,c)] = gMult(0x0b, s0c) ^ gMult(0x0d, s1c) ^ \
            gMult(0x09, s2c) ^ gMult(0x0e, s3c)
            
    return state

def subWord(word):
    """applies the sbox to the word"""
    for i in range(Nb):
        word[i] = sbox[word[i]]
    return word

def expandKey(key):
    """Expands the key using the appropriate key scheduling """
    
    # put your code here
    roundKeys = bytearray();

    for i in range(Nk):
        roundKeys.extend([key[lInd(i,0)], key[lInd(i,1)],
                         key[lInd(i,2)], key[lInd(i,3)]])

    for i in range(Nk, Nb * (Nr + 1)):
        temp = []
        temp.extend([roundKeys[lInd((i-1),0)], roundKeys[lInd((i-1),1)],
                    roundKeys[lInd((i-1),2)], roundKeys[lInd((i-1),3)]])

        if (i % Nk) == 0:
            temp = subWord(rotateWord(temp, 1))
            temp[0] ^= Rcon[i//Nk]
        elif (Nk > 6) and (i % Nk == 4):
            temp = subWord(temp)
        for j in range(Nb):
            val = roundKeys[lInd((i-Nk),j)] ^ temp[j]
            roundKeys.append(val)

    return roundKeys
              
def AES_encrypt(plaintext,key):
    """Performs an encryption on the plaintext """

    # init state
    state = bytearray(plaintext)
    state = transpose(state)
    # put your code here
    r = 0;
    roundKeys = expandKey(key)
    state = addRoundKey(state, roundKeys, r)

    for r in range(1, Nr):
        state = subBytes(state)
        state = shiftRows(state)
        state = mixColumns(state)
        state = addRoundKey(state, roundKeys, r)

    r = Nr
    state = subBytes(state)
    state = shiftRows(state)
    state = addRoundKey(state, roundKeys, r) 
    # return ciphertext

    print('Final:')
    p_state(transpose(state))
    return bytearray(transpose(state))

def AES_decrypt(ciphertext,key):
    """Performs an decryption on the ciphertext """
    
    # init state
    state = bytearray(ciphertext)
    state = transpose(state)
    # put your code here
    r = Nr
    roundKeys = expandKey(key)
    state = addRoundKey(state, roundKeys, r)

    for r in range(Nr - 1, 0, -1):
        state = iShiftRows(state)
        state = iSubBytes(state)
        state = addRoundKey(state, roundKeys, r)
        state = iMixColumns(state)

    r = 0
    state = iShiftRows(state)
    state = iSubBytes(state)
    state = addRoundKey(state, roundKeys, r)
    # return ciphertext

    print('Final:')
    p_state(transpose(state))
    return bytearray(transpose(state))


### Testing your code:

# initializing sample inputs (see FIPS 197):
pt  = bytearray.fromhex('32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34')
key128 = bytearray.fromhex('2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c')
key192 = bytearray.fromhex('8e 73 b0 f7 da 0e 64 52 c8 10 f3 2b 80 90 79 e5 62 f8 ea d2 52 2c 6b 7b')
key256 = bytearray.fromhex('60 3d eb 10 15 ca 71 be 2b 73 ae f0 85 7d 77 81 1f 35 2c 07 3b 61 08 d7 2d 98 10 a3 09 14 df f4')

ct  = bytearray.fromhex('39 25 84 1d 02 dc 09 fb dc 11 85 97 19 6a 0b 32')

Nb = 4
Nk = 4
Nr = 10
my_ct = AES_encrypt(pt,key128)
if ct==my_ct:
    print('Good job encrypting!\n')
else:
    print('Still some more error fixing needed')

pt  = bytearray.fromhex('00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff')
key128 = bytearray.fromhex('00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f')
ct = bytearray.fromhex('69 c4 e0 d8 6a 7b 04 30 d8 cd b7 80 70 b4 c5 5a')
my_ct = AES_encrypt(pt,key128)
if ct==my_ct:
    print('Good job encrypting!\n')
else:
    print('Still some more error fixing needed')

my_pt = AES_decrypt(ct,key128)
if pt==my_pt:
    print('Good job decrypting!\n')
else:
    print('Still some more error fixing needed')
        

print('--------------------------------------------------- HERE 192')    
Nk = 6
Nr = 12
pt  = bytearray.fromhex('00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff')
key192 = bytearray.fromhex('00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17')
ct = bytearray.fromhex('dd a9 7c a4 86 4c df e0 6e af 70 a0 ec 0d 71 91')
my_ct = AES_encrypt(pt,key192)
if ct==my_ct:
    print('Good job encrypting!\n')
else:
    print('Still some more error fixing needed')

my_pt = AES_decrypt(ct,key192)
if pt==my_pt:
    print('Good job decrypting!\n')
else:
    print('Still some more error fixing needed')


print('-------------------------------------------------- HERE 256')    
Nk = 8
Nr = 14
pt  = bytearray.fromhex('00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff')
key256 = bytearray.fromhex('00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f')
ct = bytearray.fromhex('8e a2 b7 ca 51 67 45 bf ea fc 49 90 4b 49 60 89')
my_ct = AES_encrypt(pt,key256)
if ct==my_ct:
    print('Good job encrypting!\n')
else:
    print('Still some more error fixing needed')

my_pt = AES_decrypt(ct,key256)
if pt==my_pt:
    print('Good job decrypting!\n')
else:
    print('Still some more error fixing needed')



print('------------------------------------------------- HERE Homeword Solution')
Nk = 4
Nr = 10
pt  = bytearray.fromhex('E5 5C D4 A8 EE E5 7D 26 1C 16 CA FE C9 40 A9 44')
key128 = bytearray.fromhex('00 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15')
ct = bytearray.fromhex('1C B8 0D 8C D9 C8 A3 53 B3 B3 AA 8B C5 2D 3B 28')
my_ct = AES_encrypt(pt,key128)
if ct==my_ct:
    print('Good solving the homework!\n')
else:
    print('Still some more error fixing needed')

my_pt = AES_decrypt(ct,key128)
if pt==my_pt:
    print('Good job decrypting the homework encrypted text!\n')
else:
    print('Still some more error fixing needed')
