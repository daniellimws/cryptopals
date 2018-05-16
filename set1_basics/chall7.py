from Crypto.Cipher import AES

KEY = 'YELLOW SUBMARINE'
aes = AES.new(KEY, AES.MODE_ECB)
ciphertext = ''
for lines in open('7.txt', 'r'):
	ciphertext += lines.strip()
ciphertext = ciphertext.decode('base64')

print aes.decrypt(ciphertext)
