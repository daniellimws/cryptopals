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

if __name__ == '__main__':
	print pkcs7_padding("YELLOW SUBMARINE", 20).encode('hex')