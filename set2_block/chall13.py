from collections import OrderedDict
from chall9 import pkcs7_padding, strip_padding
from urllib2 import urlparse
from urllib import urlencode
from Crypto.Cipher import AES

def qs_to_dict(qs):
  return dict(urlparse.parse_qsl(qs))

def dict_to_qs(d):
  return urlencode(d)

def profile_for(email):
  return encrypt_profile(dict_to_qs(OrderedDict([('email', email), ('uid', 10), ('role', 'user')])))

def encrypt_profile(profile):
  key = '"provide" that to the "attacker"'
  aes = AES.new(key, AES.MODE_ECB)
  return aes.encrypt(pkcs7_padding(profile, 16))

def decrypt_profile(c):
  key = '"provide" that to the "attacker"'
  aes = AES.new(key, AES.MODE_ECB)
  d = strip_padding(aes.decrypt(c))
  return qs_to_dict(d)

def isadmin(profile):
  profile = decrypt_profile(profile)
  return profile['role'] == 'admin'

if __name__ == '__main__':
  # attack plan
  # 1) find aes_ecb(admin + padding)
  # 2) fill email so that 'admin' + padding is a new block by itself

  # from source we know that aes ecb is being used
  blocksize = 16

  oracle = profile_for

  # get aes_ecb('admin&uid=10&rol')
  admin_c = oracle('A'*(blocksize-6) + 'admin')[blocksize:2*blocksize]
  print '[+] admin ciphertext:', admin_c.encode('hex')

  # find size of email
  # (empty_email + email - 4) % blocksize == 0
  empty_email = 'email=&uid=10&role=user'
  email_length = blocksize - ((len(empty_email) - 4) % blocksize)
  print '[+] email length: %d' % email_length

  # get aes_ecb(blocksize * n)
  # we need this to form aes_ecb('email'+'AA...AA'+'uid=10&role=admin&uid=10&rol' + padding)
  # so that it doesn't strip our message
  padding_c = oracle('A' * (email_length - 4))[-blocksize:]
  print '[+] padding ciphertext:', padding_c.encode('hex')

  # get ciphertext which ends with 'user' + padding as a block itself
  # this would be aes_ecb(32bytes + 'user')
  c = oracle('A'*email_length)

  # replace the last block with the one containing admin
  c = c[:-blocksize] + admin_c + padding_c

  print '[+] Checking if admin:', isadmin(c)

  