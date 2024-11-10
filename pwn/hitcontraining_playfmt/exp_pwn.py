#!/usr/bin/env python3
# Date: 2024-11-08 08:19:39

from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context.binary = './playfmt'
context.log_level = 'debug'
context.timeout = 5

io = process('./playfmt')
# io = remote('127.0.0.1', 13337)
elf = ELF('./playfmt')
# libc = ELF('')


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


def cmd(i, prompt):
    sla(prompt, i)

def add():
    cmd('1')
    #......

def edit():
    cmd('2')
    #......

def show():
    cmd('3')
    #......

def dele():
    cmd('4')
    #......

sn(b'%15$p,%6$p')

ia()
