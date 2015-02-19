### This is a template file for efficient modular exponentiation functions
### and a reference implementation of RSA PKCS #1, v2.1 encryption.
##
##  Please implement the provided functions and assure that your code
##  works correctly for the example given below
##
##  Name: Laurentiu Pavel
##  Date: Feb 19th
##

import time
import sys
from math import log
sys.setrecursionlimit(4*2048)


# function that get the bits from Right to Left
def getBitsReversed(num):
    bits = []
    while(num):
        bits.append(num % 2)
        num = num // 2
    return bits

def getBits(num):
    return getBitsReversed(num)[::-1]
    
def my_pow_SqMul(x,e,n):
    ''' Performs modular exponentiation (x^e mod m)
        using the square and multiply algorithm'''

    # put your code here
    y = 1
    bits = getBits(e)
    for bit in bits:
       y = y * y % n
       if bit is 1:
           y = y * x % n 
        
    return y

def my_pow_SlWin(b,e,n,k=4):
    ''' Performs modular exponentiation (b^e mod m)
        using the sliding window algorithm with window size k'''

    # put your code here
    #precomputation
    x = []
    x.append(0) # x[0] = 0 -> doesn't matter what it is
    x.append(b)
    x.append(b*b % n)
    for i in range(1, 2**(k-1)):
        x.append(x[2*i - 1] * x[2] % n)
        x.append(0) # not used for anything but to jump to the next odd

    #exponentiation
    y = 1
    bits = getBitsReversed(e)
    
    i = len(bits) - 1
    while i > 0:
        if bits[i] is 0:
            y = y * y % n
            i = i - 1
        else:
            p = max(1 + i - k, 0)
            while bits[p] is 0:
                p = p + 1
            window = 0;
            for j in range(p, i):
                window = window | (bits[j] << (j - p))
            window = window | (bits[i] << (i - p));
                
            l = i - p + 1
            y = pow(y, pow(2,l), n)
            y = y * x[window] % n
            i = i - l
    return y

#my implementation from project 1
def my_pow_P1(b,e,m):
    """ Computes b^e mod m using the square and multiply algorithm"""
    if e == 0:
        return 1

    ## enter your source code here
    x = 1
    n = b
    bit_pos = 1
    while bit_pos <= e:
        if e & bit_pos:
            x = (x * b) % m
        b = (b * b) % m
        bit_pos = bit_pos << 1

    
    return x



def MGF(seed,maskLen):
    '''returns a mask of length maskLen, generated from seed using SHA-256'''
    import hashlib
    import math
    
    T=bytearray()
    hLen = hashlib.sha256().digest_size # since we use SHA256
    
    #put your code here

    for cnt in range(math.ceil(maskLen/hLen)):
        T = T + bytearray(hashlib.sha256(
            seed + bytearray(cnt.to_bytes(4, byteorder='big'))).digest())
    return T [:maskLen]

def bytes_size(n):
    if n == 0:
        return 1
    return int(log(n, 256)) + 1


def RSAESencrypt(N,e,m,L=bytearray()):
    '''Performs RSA PKCS #1 v2.1 encryption using the public key <N,e>
        on message m (optinal: label L). Ciphertext c is returned.
        N and e are integers, m, L, and c are byte arrays'''

    import hashlib
    import os
    import binascii
    
    mLen = len(m)
    hLen = hashlib.sha256().digest_size # since we use SHA256
    k = bytes_size(N)

    # put your code here:

    # check lengths
    is_long = False;
    if len(m) > (k - (2 * hLen) - 2):
        is_long = True;
    # generate DB
    PS_size = (k - hLen - 1) - (1 + mLen + hLen)
    PS = bytearray(0 for x in range(PS_size))
    DB = bytearray(hashlib.sha256(L).digest()) + bytearray(PS) + bytearray(b'\x01') + m
    if is_long is True:
        raise IOError('encryption error')
    # seeding and masking
    seed = os.urandom(hLen)
    DBmask = MGF(seed, k - hLen - 1)
    maskedDb = bytearray()
    for i in range(len(DB)):
        maskedDb.append(DBmask[i] ^ DB[i])
    seedMask = MGF(maskedDb, hLen)
    maskedSeed = bytearray()
    for i in range(len(seed)):
        maskedSeed.append(seedMask[i] ^ seed[i])

    # generate EM
    EM = bytearray(b'\x00') + maskedSeed + maskedDb
    # perform encryption
    message = int.from_bytes(EM, byteorder='big', signed=False)
    cipherInt = pow(message, e, N)
    
    cipherBytes = bytearray(cipherInt.to_bytes(k, byteorder='big'))
    
    
    return cipherBytes

def RSADAP(K, c):
    if c < 0 or c > (N - 1):
        raise IOError('ciphertext representative out of range')
    return pow(c,d,N)

def RSAESdecrypt(N,d,c,L=bytearray()):
    '''Performs RSA PKCS #1 v2.1 decryption using the private key <N,d>
        on ciphertext c (optinal: label L). Message m is returned.
        N and d are integers, m, L, and c are byte arrays'''

    import hashlib
    import os


    cLen = len(c)
    hLen = hashlib.sha256().digest_size # since we use SHA256
    k = bytes_size(N)

    # put your code here:
    # check lengths
    if len(L) > hLen:
        raise IOError('Decryption Error')
    if cLen is not k:
        raise IOError('Decryption Error')
    if k < (2 * hLen + 2):
        raise IOError('Decryption Error')
    
    # decrypt C
    cipherInt = int.from_bytes(c, byteorder='big', signed=False)
    m = RSADAP(k, cipherInt)
    EM = bytearray(m.to_bytes(k, byteorder='big'))
    # separate EM
    Y = EM[0]
    maskedSeed = EM[1:hLen + 1]
    maskedDb   = EM[hLen+1:]

    # remove masks
    seedMask = MGF(maskedDb, hLen)
    seed = bytearray()
    for i in range(len(seedMask)):
        seed.append(maskedSeed[i] ^ seedMask[i])

    dbMask = MGF(seed, k - hLen - 1)
    DB = bytearray()
    for i in range(len(dbMask)):
        DB.append(maskedDb[i] ^ dbMask[i])

    lHash = DB[:hLen]
    i = hLen
    while DB[i] is 0:
        i = i + 1

    is_issue = False
    if DB[i] is not 1:
        is_issue = True

    m = DB[i+1:]
        
    # check DB
    if is_issue is True:
        raise IOError('decryption error')

    #Note.  Care must be taken to ensure that an opponent cannot
    #distinguish the different error conditions in Step 3.g, whether by
    #error message or timing, or, more generally, learn partial
    #information about the encoded message EM.  Otherwise an opponent may
    #be able to obtain useful information about the decryption of the
    #ciphertext C, leading to a chosen-ciphertext attack such as the one
    #observed by Manger
    
    return m
    
    
        
p =  997782014483135516947467112733783206034059987091508997470391422588302757009297888172824321316039986332404368187672035334285863264469832007564899663393813987428733469948510589362567714925225591609164647780163771437334778893745924369236957875430167009790722454797434933978389194431730946950351883503681 
q = 79301961686790288135761596161932125982627215111620602465105295605167614622099617732042554017601029601972431354155023876998569040821697397911153196884814759437163993503206804558864234356549520950879755905643095880867184872343043391321834768955404845085269931482274291437512222693097323499756682477811051
#p = 8176662165573700613347344450959887037086515168356394479546398903326976319674343656956828452558146536261756580874692178418735952635936011308339369316896181
#q = 13062362680240858986014063047218740765842583586324085493117801839987719301360641696613806125427125208683501703668298486807198605540347486024024409678675789

N = p*q

b = 3
#e = 2**1000-1
e = 2**2024 - 3463456347 # much better e that doesn't have only ones
m = N

tic = time.clock()
out = pow(b,e,m)
toc = time.clock()
Tpow = toc-tic

tic = time.clock()
out2 = my_pow_SqMul(b,e,m)
toc = time.clock()
Tsqmul=toc-tic

tic = time.clock()
out3 = my_pow_SlWin(b,e,m)
toc = time.clock()
Tslwin=toc-tic

tic = time.clock()
out4 = my_pow_P1(b,e,m)
toc = time.clock()
TMyPowP1=toc-tic




if(out == out2):
    print('Square and multiply: works (in ',Tsqmul,'s)')
else:
    print('Square and multiply: failed')

if(out == out3):
    print('Sliding Window:      works (in ',Tslwin,'s)')
else:
    print('Sliding Window:      failed')

if(out == out4):
    print('My log pow from Project 1:      works (in ',TMyPowP1,'s)')
else:
    print('My log pow from Project 1:      failed')





# Testing RSA encryption and decryption
# don't mess with tese numbers:
p = 8176662165573700613347344450959887037086515168356394479546398903326976319674343656956828452558146536261756580874692178418735952635936011308339369316896181
q = 13062362680240858986014063047218740765842583586324085493117801839987719301360641696613806125427125208683501703668298486807198605540347486024024409678675789
N = p*q
e = 2**16+1
d = 95305639297136535129830247353885048571790931736897092024327830574503233416208940851818667509421055075611745557004095412620624213281032376171998990351263574092801357243118351700307075125243451771395731520183667695423762834718377372357353733379277776224241008883890378073612334038347526558549705139740335907073

# Test MGF:
print('Starting MGF Test: ',end = '')
seed = bytearray()
for cnt in range(33):
    seed.append(cnt)

check = MGF(seed,42)
correct = bytearray(b'_\xf0\x98\xa3\xa9\xe7\xa9=\xc6\x04\x99\xf1\xa6\xfb\xf6\x8cW\x9c\x90B\xd6\x9cEs\x1d\xf9\xd7\xa8\x0e\xfb)\xaf\xc0\xc9\n=\x9e\x8a\x11\x18o;')
if len(check)!=42:
    print('error: wrong output length')
elif(check != correct):
    print('failed: wrong output')
else:
    print('passed')


# Test RSA Encryption and decryption:
print('Starting first RSA Test: ',end = '')

m = bytearray(b'\x02\xff')
c = RSAESencrypt(N,e,m)
mp = RSAESdecrypt(N,d,c)
if (mp!=m):
    print('failed: message not recovered')
else:
    print('passed')
# DB= bytearray(b"\xe3\xb0\xc4B\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99o\xb9$\'\xaeA\xe4d\x9b\x93L\xa4\x95\x99\x1bxR\xb8U\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x02\xff"

print('Starting second RSA Test: ',end = '')
m = correct
c = RSAESencrypt(N,e,m)
mp = RSAESdecrypt(N,d,c)
if (mp!=m):
    print('failed: message not recovered')
else:
    print('passed')
# DB= bytearray(b"\xe3\xb0\xc4B\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99o\xb9$\'\xaeA\xe4d\x9b\x93L\xa4\x95\x99\x1bxR\xb8U\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01_\xf0\x98\xa3\xa9\xe7\xa9=\xc6\x04\x99\xf1\xa6\xfb\xf6\x8cW\x9c\x90B\xd6\x9cEs\x1d\xf9\xd7\xa8\x0e\xfb)\xaf\xc0\xc9\n=\x9e\x8a\x11\x18o;")

print('Starting first RSA Failure Test: ',end = '')

m = correct+correct+correct
try:
    c = RSAESencrypt(N,e,m)
except IOError:
    print('passed')
else:
    print('failed')

print('Starting second RSA Failure Test: ',end = '')

c = b"A\xe0\xe5\xe6G)\xbc\x04\xd3'\xe50@/\xddiy\xff\xd0\x8b\xc8U\x10p\xf5v{`\xa7\x19o\xe5\xb3X~\x10\xbf7eN\x9ey\x9f\x1d\xe9\xe8\x89\xbcxX\xee\x95\xf5\xdf\xc7M\x91\xc3\x84C\x15]a\xf9\xcf]\xb4r\x06\xb8QL\x86\x19^NF\xd2\xf6|\xeb\x10G\xc6\x0b\x87\x07\xd1O\xff(\xadk\xe1Cj\xfc\xbc=\xee\x16cc\xb69\xb3\xcb\x92 e+G\x1f\x85&~4p\xc2\x8f]\xf2\xfb\xee\xa6\xe2oJ"
try:
    m = RSAESdecrypt(N,e,c)
except IOError:
    print('passed')
else:
    print('failed')


