def strip_padding(s):
  pad_bytes = ord(s[-1])
  if s[-pad_bytes:] == chr(pad_bytes) * pad_bytes:
  	return s[:-pad_bytes]
  raise ValueError('Invalid padding')