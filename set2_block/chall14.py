import random, string
import sys
from chall9 import pkcs7_padding
from Crypto.Cipher import AES

def random_bytes(n):
  return ''.join([chr(random.randint(0, 0xff)) for i in range(n)])

def oracle(s):
  global key, prefix
  aes = AES.new(key, AES.MODE_ECB)
  c = open('14.txt', 'r').read().decode('base64')
  return aes.encrypt(pkcs7_padding(prefix + s + c, len(key)))

def decrypt_block(oracle, prefix, message_block_num, brute_block_num, block_offset):
  sz = 16
  d = ''
  for i in range(sz):
    mapping = dict([(oracle('A' * block_offset + prefix + d + chr(c))[sz*brute_block_num:sz*(brute_block_num+1)], chr(c)) for c in range(0, 0x100)])

    # assuming we cannot send in an empty string
    # we cannot do oracle('') to get aes('' + hidden_message)
    # we get the next block, oracle('A'*sz)[sz:2*sz], i.e. aes('A'*sz + hidden_message)[sz:2*sz]
    if i == sz - 1:
      block = oracle('A' * block_offset + 'A'*sz)[sz*(message_block_num+1):sz*(message_block_num+2)]
    else:
      block = oracle('A' * block_offset + prefix)[sz*message_block_num:sz*(message_block_num+1)]

    d += mapping[block]
    if not mapping[block] in string.printable:
      return d

    prefix = prefix[1:]

  return d

def break_aes_ecb(oracle, block_num, block_offset):
  # now trying to break byte by byte
  block_size = 16
  d = ''
  prefix = 'A' * (block_size - 1)
  i = block_num + 1

  # we don't know the length of plaintext, so just keep running until we get a non-printable byte
  # which most likely is the padding
  while len(d) == 0 or d[-1] in string.printable:
    d_block = decrypt_block(oracle, prefix, i, block_num + 1, block_offset)
    prefix = d_block[1:]
    d += d_block
    i += 1

  return d[:-1]

if __name__ == '__main__':
  global key, prefix
  key = random_bytes(16)
  prefix = random_bytes(random.randint(0, 200))

  # information provided is we have control over user_bytes in
  # AES-128-ECB(random-prefix || user_bytes || target-bytes, random-key)

  # attack plan
  # 1) find which block are we in
  # 2) find the offset of us inside the block (from the end, i.e. how many more bytes to finish a block)
  # 3) perform attack as usual

  block_size = 16

  # find block number
  # whichever block is affected by our output would be the block we are in
  block_num = 0
  c1 = oracle('A')
  c2 = oracle('B')

  while c1[block_num*block_size:(block_num + 1)*block_size] == c2[block_num*block_size:(block_num + 1)*block_size]:
    block_num += 1

  print '[+] Block number: %d' % block_num

  # find block offset (from the end of the block)
  block_offset = 1
  while oracle('A' * block_offset)[:(block_num + 1)*block_size] != oracle('A' * (block_offset + 1))[:(block_num + 1)*block_size]:
    block_offset += 1

  print '[+] Block offset: %d' % block_offset

  # decrypt target bytes
  print break_aes_ecb(oracle, block_num, block_offset)
