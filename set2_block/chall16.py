from chall10 import *
from urllib import quote_plus

def random_bytes(n):
  return ''.join([chr(random.randint(0, 0xff)) for i in range(n)])

def oracle(s):
  global prefix, suffix, key, iv
  s = quote_plus(s)
  return encrypt_aes_cbc(prefix + s + suffix, key, iv)

def is_admin(c):
  global prefix, suffix, key, iv
  m = decrypt_aes_cbc(c, key, iv).split(';')
  d = {}
  for i in m:
    d[i.split('=')[0]] = i.split('=')[1]
  return 'admin' in d and d['admin'] == 'true'

# helper function to apply same bit flipping operation to target
def bit_flip(c_from, c_to, target):
  return chr(ord(target) ^ ord(c_from) ^ ord(c_to))

if __name__ == '__main__':
  global prefix, suffix, key, iv
  prefix = "comment1=cooking%20MCs;userdata="
  suffix = ";comment2=%20like%20a%20pound%20of%20bacon"
  key = random_bytes(16)
  iv = random_bytes(16)

  blocksize = 16

  # attack plan
  # 1) pad prefix so that it is a multiple of block size
  # 2) have a block full of As, this block's ciphertext will be used for our bit flipping,
  #    so that scrambling anything inside here only affects the next block, because
  #    we don't want to affect anything else.
  #    Call this block1
  # 3) another block full of As, the plaintext resulted by this block will be
  #    affected by bit flipping in block1.
  #    Call this block2
  # 4) Flip the bits necessary inside ciphertext of block1 to transform plaintext of block2
  #    into AAAAAAadmin=true

  # pad prefix
  padding = 'A' * (blocksize - (len(prefix) % blocksize))

  # block1
  block1 = 'A' * blocksize

  # block2
  block2 = 'AAAAAAadminAtrue'

  # get the ciphertext so that we can start flipping
  c = oracle(padding + block1 + block2)

  # we want to flip from
  # AAAAAAadminAtrue    to
  # AAAAA;admin=true
  c = list(c)
  offset = len(prefix + padding)
  c[offset + 5] = bit_flip('A', ';', c[offset + 5])
  c[offset + 11] = bit_flip('A', '=', c[offset + 11])
  c = ''.join(c)

  print is_admin(c)
