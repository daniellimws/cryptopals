from chall3 import decrypt_single_xor

filepath = '4.txt'
ds = []
for line in open(filepath, 'r'):
	print line.strip()
	line = line.strip().decode('hex')
	ds += decrypt_single_xor(line)
print'----'
ds.sort(key=lambda x: x[0], reverse=True)
print '\n'.join(d[2] for d in ds[:10])