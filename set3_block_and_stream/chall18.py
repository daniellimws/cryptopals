from pwn import *
from Crypto.Cipher import AES

c = 'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=='.decode('base64')

def encrypt_aes_ctr(msg, key, iv):
    aes = AES.new(key, AES.MODE_ECB)
    
    c = ''
    for i in range(len(msg) / 16):
        keystream = aes.encrypt(p64(iv) + p64(i))
        c += xor(keystream, msg[i*16:(i+1)*16])

    return c

def decrypt_aes_ctr(c, key, iv):
    aes = AES.new(key, AES.MODE_ECB)

    d = ''
    for i in range(len(c) / 16):
        keystream = aes.encrypt(p64(iv) + p64(i))
        d += xor(keystream, c[i*16:(i+1)*16])

    return d

if __name__ == '__main__':
    print decrypt_aes_ctr(c, 'YELLOW SUBMARINE', 0)


