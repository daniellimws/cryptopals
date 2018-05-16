def xor_2_str(s1, s2):
	unhex1 = s1.decode('hex')
	unhex2 = s2.decode('hex')
	combine = ''.join(chr(ord(unhex1[i]) ^ ord(unhex2[i])) for i in range(len(unhex1)))
	return combine.encode('hex')

print xor_2_str('1c0111001f010100061a024b53535009181c', '686974207468652062756c6c277320657965')