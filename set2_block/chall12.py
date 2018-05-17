import random, string
import sys
from chall9 import pkcs7_padding
from Crypto.Cipher import AES

def random_bytes(n):
  return ''.join([chr(random.randint(0, 0xff)) for i in range(n)])

def oracle(s):
  global key
  aes = AES.new(key, AES.MODE_ECB)
  c = open('12.txt', 'r').read().decode('base64')
  return aes.encrypt(pkcs7_padding(s + c, len(key)))

def is_aes_ecb(s, n):
  for i in range(len(s) - n + 1):
    if s[i:i+n] in s[i+n:]:
      return True
  return False

def decrypt_block(oracle, prefix, block_num):
  sz = len(prefix) + 1
  d = ''
  for i in range(sz):
    mapping = dict([(oracle(prefix + d + chr(c))[:sz], chr(c)) for c in range(0, 0x100)])

    # assuming we cannot send in an empty string
    # we cannot do oracle('') to get aes('' + hidden_message)
    # we get the next block, oracle('A'*sz)[sz:2*sz], i.e. aes('A'*sz + hidden_message)[sz:2*sz]
    if i == sz - 1:
      block = oracle('A'*sz)[sz*(block_num+1):sz*(block_num+2)]
    else:
      block = oracle(prefix)[sz*block_num:sz*(block_num+1)]

    d += mapping[block]
    if not mapping[block] in string.printable:
      return d

    prefix = prefix[1:]

  return d

def break_aes_ecb(oracle):
  # now trying to break byte by byte
  block_size = 16
  d = ''
  prefix = 'A' * (block_size - 1)
  i = 0

  # we don't know the length of plaintext, so just keep running until we get a non-printable byte
  # which most likely is the padding
  while len(d) == 0 or d[-1] in string.printable:
    d_block = decrypt_block(oracle, prefix, i)
    prefix = d_block[1:]
    d += d_block
    i += 1

  return d[:-1]

if __name__ == '__main__':
  global key
  key = random_bytes(16)

  # to check block size
  prev = oracle('A')
  block_size = 1
  while oracle('A' * (block_size + 1))[:block_size] != prev:
    block_size += 1
    prev = oracle('A' * block_size)[:block_size]

  assert block_size == 16

  # to check if it is ecb
  c = oracle('A' * block_size * 2)
  assert c[:block_size] == c[block_size:2*block_size]

  print break_aes_ecb(oracle)