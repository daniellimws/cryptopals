from pwn import *

msg = 'Burning \'em, if you ain\'t quick and nimble\nI go crazy when I hear a cymbal'

print xor(msg, 'ICE').encode('hex')