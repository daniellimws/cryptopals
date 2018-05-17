from chall9 import pkcs7_padding, strip_padding
from Crypto.Cipher import AES
from pwn import *

def encrypt_aes_cbc(s, key, iv):
  s = pkcs7_padding(s, 16)
  aes = AES.new(key, AES.MODE_ECB)
  prev = iv
  c = ''
  for i in range(len(s) // 16):
    block = s[i*16:(i+1)*16]
    block = xor(block, prev)
    block = aes.encrypt(block)
    c += block
    prev = block

  return c

def decrypt_aes_cbc(s, key, iv):
  aes = AES.new(key, AES.MODE_ECB)
  prev = iv
  d = ''
  for i in range(len(s) // 16):
    block = s[i*16:(i+1)*16]
    prev, block = block, xor(aes.decrypt(block), prev)
    d += block
  
  return strip_padding(d)

if __name__ == '__main__':
  c = ''
  for lines in open('10.txt', 'r'):
    c += lines.strip()
  c = c.decode('base64')

  print decrypt_aes_cbc(c, 'YELLOW SUBMARINE', '\x00'*16)

assert decrypt_aes_cbc(encrypt_aes_cbc('TESTING THIS WORKS', 'YELLOW SUBMARINE', '\x00'*16), 'YELLOW SUBMARINE', '\x00'*16) == 'TESTING THIS WORKS'
