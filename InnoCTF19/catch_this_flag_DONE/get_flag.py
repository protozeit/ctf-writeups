#!/usr/bin/env python
import re
from pwn import *
context.log_level = 'critical'

port = 46470
flag = ''
started = 0
prev = ''

while True:
    con = remote('188.130.155.66', port)
    text = con.recv()
    # print text
    if "cats" in text: # No cats here...
        if started == 0:
            port += 1
        con.close()
        continue
    elif "flag" in text: # Your part of the flag is:43
        started = 1      # Next port:46473
        port = int(re.findall('4647.',text)[0])
        prev = re.findall('Your part of the flag is:..', text)[0][-2:]
        if prev == flag[-2:] and flag != '':
            continue
        flag += prev
    print flag
    con.close()
