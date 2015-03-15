### This is a template file for Project 3.
##
##  Please implement the provided function and assure that your code
##  works correctly. Please submit your code together with the 
##  requested answers through blackboard
##
##  Name: Laurentiu Pavel
##  Date: TODO
##

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

# Problem 3: 
'''
ciphertext1 = int.to_bytes(0xe719f8ab9e0b846f0cf2e5c32a0e5b45,16,'big')
faultytext1 = int.to_bytes(0xe719f86f9e0beb6f0c97e5c38b0e5b45,16,'big')

ciphertext2 = int.to_bytes(0x78f272c7cf5383085fa240236d97130f,16,'big')
faultytext2 = int.to_bytes(0x78f27277cf53e7085f944023fa97130f,16,'big')
'''

ciphertext1 = bytearray.fromhex('e719f8ab9e0b846f0cf2e5c32a0e5b45')
faultytext1 = bytearray.fromhex('e719f86f9e0beb6f0c97e5c38b0e5b45')

ciphertext2 = bytearray.fromhex('78f272c7cf5383085fa240236d97130f')
faultytext2 = bytearray.fromhex('78f27277cf53e7085f944023fa97130f')


Nb = 4

# returns the equivalent of the matrix position into a list
def transpose(state):
    """Transposes a matrix. Done because the plaintext decryption comes
        exactly the oposite than how the operations need to be made."""
    newState = []
    for i in range(Nb):
        for j in range(Nb):
            newState.append(state[lInd(j,i)])
    return newState


def lInd(i,j):
    return i*Nb + j

def gMult(a, b):
    """Taken from project 1"""
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

def mixCols(state):
    """Taken from project 1"""
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

def addRoundKey(state, key):
    """Adds (XORs) the round key to the state."""
    
    # put your code here
    for i in range(Nb):
        for j in range(Nb):
            state[lInd(j,i)] ^= key[lInd(j, i)]
    return state

def padHex(hexStr, numBits):
    for i in range(len(hexStr), numBits):
        hexStr = hexStr + "0"
    return hexStr[::-1]
    

def AESFaultAttack(ct,ft):
    ''' performs a key recovery attack on four bytes of the key
        using a correct and a faulty AES ciphertext.
        the function returns a list of subkey candidates.'''
    candidates = []
    regMixCols = mixCols(ct)
    ct = transpose(ct)
    ft = transpose(ft)
    for delta in range(0, 255):
        deltaState = transpose(bytearray.fromhex('00 00 00 00 00 00 00 00 00 00 00 00 00 00 ' +
                                       padHex(str(hex(delta)[2:]), 4)))
        deltaMixCols = mixCols(deltaState)
        for i in range(16):
            print("dmi" + str(i) + ":" + str(deltaMixCols[i]))
        k1 = 0
        k2 = 0
        k3 = 0
        k4 = 0
        for k1 in range(0, 255):
#            print("k1 here")
            key = transpose(bytearray.fromhex('00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00' +
                                              padHex(str(hex(k1)[2:]),2) + padHex(str(hex(k2)[2:]),2) +
                                              padHex(str(hex(k3)[2:]),2)  + padHex(str(hex(k4)[2:]),2) ))
            if addRoundKey(iSubBytes(addRoundKey(ct,key)),
                           iSubBytes(addRoundKey(ft,key)))[12] == deltaState[12]:
                for k2 in range(0, 255):
#                    print("k2 here")
                    key = transpose(bytearray.fromhex('00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00' +
                                                      padHex(str(hex(k1)[2:]),2) + padHex(str(hex(k2)[2:]),2) +
                                                      padHex(str(hex(k3)[2:]),2)  + padHex(str(hex(k4)[2:]),2) ))
                    if addRoundKey(iSubBytes(addRoundKey(ct,key)),
                                   iSubBytes(addRoundKey(ft,key)))[9] == deltaState[13]:
                        for k3 in range(0, 255):
#                            print("k3 here")
                            key = transpose(bytearray.fromhex('00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00' +
                                                              padHex(str(hex(k1)[2:]),2) + padHex(str(hex(k2)[2:]),2) +
                                                              padHex(str(hex(k3)[2:]),2)  + padHex(str(hex(k4)[2:]),2) ))
                            if addRoundKey(iSubBytes(addRoundKey(ct,key)),
                                           iSubBytes(addRoundKey(ft,key)))[6] == deltaState[14]:
                                for k4 in range(0, 255):
#                                    print("k4 here")
                                    key = transpose(bytearray.fromhex('00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00' +
                                                                      padHex(str(hex(k1)[2:]),2) + padHex(str(hex(k2)[2:]),2) +
                                                                      padHex(str(hex(k3)[2:]),2)  + padHex(str(hex(k4)[2:]),2) ))
                                    if addRoundKey(iSubBytes(addRoundKey(ct,key)),
                                                   iSubBytes(addRoundKey(ft,key)))[3] == deltaState[15]:
#                                        print("k:" + str(transpose(key)))
                                        candidates.append(key); 
    return candidates

keys = set()

def lists_overlap(a, b):
        return bool(set(a) & set(b))

if __name__ == "__main__":
       
    candidates1 = AESFaultAttack(ciphertext1, faultytext1)
    candidates2 = AESFaultAttack(ciphertext2, faultytext2)

#    print(lists_overlap(candidates1,candidates2))

    
    for candidate in candidates1:
        if candidate in candidates2:
            print(str(candidate) + " - yes")
        else:
            print(str(candidate) + " - no")
    
    
#    print sharedItem(candidates1, candidates2)
    

# Note: after performing the attack twice, you can find the
#       matching candidates for both cases. this will leave
#       you with only one remaining candidate.
