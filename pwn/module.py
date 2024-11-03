#!/usr/bin/env python3

from pwn import *
from LibcSearcher import *

context(os = 'linux',arch = 'amd64',log_level = 'debug')

file_name = ''
lib_name = ''
debug = 1
if debug:
    p = process(file_name)
    context.terminal = ['tmux','splitw','-h']
    # gdb.attach(p)
else:
    ip = 'node5.buuoj.cn'
    port = ''
    p = remote(ip, port)
elf = ELF(file_name)
rop = ROP(file_name)
# libc = ELF(lib_name)

