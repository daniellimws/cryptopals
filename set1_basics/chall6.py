from __future__ import division
from pwn import *
from chall3 import decrypt_single_xor

def hamming_distance(s1, s2):
  total = 0
  for i in range(len(s1)):
    bin1 = '{0:08b}'.format(ord(s1[i]))
    bin2 = '{0:08b}'.format(ord(s2[i]))
    for j in range(len(bin1)):
      total += abs(ord(bin1[j]) - ord(bin2[j]))
  return total

def transpose(s, sz):
  return [s[i::sz] for i in range(sz)]

def break_repeating_xor(s, kmin, kmax, nblocks, ntries):
  scores = []
  for i in range(kmin, kmax + 1):
    score = 0
    for j in range(nblocks):
      score += hamming_distance(s[j*i:(j+1)*i], s[(j+1)*i:(j+2)*i])
    score /= nblocks
    scores.append((score / i, i))

  scores.sort(key=lambda x: x[0])

  ds = []
  for i in range(ntries):
    key = ''
    for block in transpose(s, scores[i][1]):
      d = decrypt_single_xor(block)
      key += chr(d[0][1])

    ds.append((scores[i][1], key, xor(key, s)))

  return ds

msg = ''
for lines in open('6.txt', 'r'):
  msg += lines.strip()
msg = msg.decode('base64')
d = break_repeating_xor(msg, 2, 40, 9, 1)[0]
print "Key:", d[1]
print "--------"
print "Message:"
print d[2]