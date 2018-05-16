from Crypto.Cipher import AES

def is_aes_ecb(s):
  for i in range(len(s) - 16 + 1):
    if s[i:i+16] in s[i+16:]:
      return True
  return False

for lines in open('8.txt', 'r'):
  c = lines.strip().decode('hex')
  if is_aes_ecb(c):
    print(c.encode('hex'))
