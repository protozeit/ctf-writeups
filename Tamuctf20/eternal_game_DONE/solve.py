#!/usr/bin/env python

from pwn import *
import hashpumpy

# r = remote("challenges.tamuctf.com", 8812)
r = process(["python2", "game.py"])

# context.log_level = 'DEBUG'

proof_for_6 = "1ec356a3f23437e5350a1288a270bf221af33ec1c8b7d5147738e532534fb0b1ee5678e1cbba120b27b1d20c3ac5c2479be7b139b9181ead93fc841a50f8237b"
score = "6530860698917749044661081413060285367226191338056"

def claim_prize(score, proof):
    r.sendlineafter("3. Exit", '2')
    r.sendlineafter("Input the number you reached:", score)
    r.sendlineafter("Present the proof of your achievement:", proof)
    r.recvline()
    return r.recvline()

for l in range(1,256):
    print("trying with key of length %d" % l)
    res = hashpumpy.hashpump(proof_for_6, score[0], score[::-1][1:], l) 
    x = claim_prize(res[1], res[0])
    if b"Don't play games with me" in x:
        continue
    else:
        print(x)
        break

r.interactive()
