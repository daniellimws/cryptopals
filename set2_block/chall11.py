from chall9 import pkcs7_padding
from chall10 import encrypt_aes_cbc, decrypt_aes_cbc
from Crypto.Cipher import AES
import random

def random_bytes(n):
  return ''.join([chr(random.randint(0, 0xff)) for i in range(n)])

def encrypt_random(s):
  key = random_bytes(16)
  iv = random_bytes(16)

  s = random_bytes(random.randint(5, 10)) + s + random_bytes(random.randint(5, 10))
  s = pkcs7_padding(s, 16)

  if random.randint(0, 1) == 0:
    # do ecb
    aes = AES.new(key, AES.MODE_ECB)
    return ('ECB', aes.encrypt(s))
  else:
    return ('CBC', encrypt_aes_cbc(s, key, iv))

def is_aes_ecb(s, n):
  for i in range(len(s) - n + 1):
    if s[i:i+n] in s[i+n:]:
      return True
  return False

def aes_oracle(s):
  if is_aes_ecb(s, 16):
    return 'ECB'
  return 'CBC'

if __name__ == '__main__':
  m = open('11.txt', 'r').read() # 11.txt is not provided, it is my own text
  score = 0
  for i in range(25):
    c = encrypt_random(m)
    print c[0], aes_oracle(c[1])
    if c[0] == aes_oracle(c[1]):
      score += 1

  print '%d/25' % score
