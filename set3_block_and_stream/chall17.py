import random
from pwn import *
from Crypto.Cipher import AES

#############################################################################################
#                                                                                           #
# All the functions invovled for the challenge                                              #
#                                                                                           #
#############################################################################################

def pkcs7_padding(s, sz):
  if len(s) % sz == 0 and len(s) > ord(s[-1]) and s[-(ord(s[-1]) + 1):] == s[-1] * ord(s[-1]):
    return s + chr(sz) * sz
  n = sz - (len(s) % sz)
  return s + chr(n) * n

def strip_padding(s):
  pad_bytes = ord(s[-1])
  if s[-pad_bytes:] == chr(pad_bytes) * pad_bytes:
    return s[:-pad_bytes]
  raise ValueError('Invalid padding')

def random_bytes(n):
  return ''.join([chr(random.randint(0, 0xff)) for i in range(n)])

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

def get_encrypted_message():
  global key, lines, iv
  line = lines[random.randint(0, len(lines) - 1)].decode('base64')
  print "Supposed: " + line
  iv = random_bytes(16)
  c = encrypt_aes_cbc(line, key, iv)
  return c, iv

def oracle(c):
  global key, iv
  try:
    decrypt_aes_cbc(c, key, iv)
  except ValueError:
    return False

  return True


#############################################################################################
#                                                                                           #
# Everything above this are the functions for the challenge, none is under our control      #
#                                                                                           #
# Treat them like a web server, and all we have access to is the oracle, which tells us     #
# whether our ciphertext is valid or not after stripping.                                   #
#                                                                                           #
# We use a padding oracle attack to find the plaintext.                                     #
#                                                                                           #
#############################################################################################

# the core of this attack
# finds the intermediate term for each block
# c must be exactly one block
def find_intermediate(c, oracle):
  intermediate = ''

  # loops through each character in a block
  for i in range(16):
    # the suffix prepares the end of the block
    # for example i = 3, this makes sure the block after decryption ends with '\x04\x04\x04'
    # so that we can use brute force to find the intermediate that makes it '\x04\x04\x04\x04'
    iv_suffix = ''
    for j in range(i):
      iv_suffix = chr(ord(intermediate[-(j + 1)]) ^ (i + 1)) + iv_suffix

    # brute force try every byte and see which one doesnt give us an exception when trying to strip the padding off
    for j in range(0x100):
      # just making sure the previous block is block_size long
      iv = (chr(j) + iv_suffix).rjust(16)

      # we found it!
      if oracle(iv + c):
        intermediate = chr((i + 1) ^ j) + intermediate
        break
      
    # this means we failed to obtain the corresponding byte for the intermediate in this position
    if len(intermediate) != i + 1:
      raise Exception("Oops failed to find")

  return intermediate

def padding_oracle_attack(c, iv, oracle):
  result = ''
  for i in range(len(c) / 16):
    intermediate = find_intermediate(c[i * 16:(i+1) * 16], oracle)

    # since we got the intermediate we just need to xor it with the previous ciphertext block to obtain the plaintext
    previous_block = c[(i-1)*16:i*16] if i != 0 else iv
    result += xor(previous_block, intermediate)

  print strip_padding(result)


if __name__ == '__main__':
  global lines, key, iv
  lines = open('17.txt', 'r').read().split('\n')
  key = random_bytes(16)

  c, iv = get_encrypted_message()

  # we only have c and iv here
  # we want to do a padding oracle attack
  # oracle tells us whether the ciphertext is properly padded

  # attack plan
  # for each block
  # 1) find the last intermediate character, by bruteforcing the cipher block that leads
  #    to \x01
  # 2) now we can control the last character of plaintext to be \x02, and brute force to find second last intermediate value
  # 3) repeat until we get the whole intermediate value block, xor this with given previous cipherblock to get plaintext for this block
  #     * for the first block, there is no previous block, xor it with the iv instead

  padding_oracle_attack(c, iv, oracle)


