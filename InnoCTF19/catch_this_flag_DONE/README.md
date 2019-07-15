# Catch This Flag!

- Category: PPC
- Rating: medium

This was a really fun challenge involving a healthy amount of cats.

We are given a ip to connect to along with 10 ports, `46470-46479`, connecting to any of them usually gets us this response
```bash
Sorry, No cats here... # As I remember it
``` 
but every once in a while you get this
```bash
 _._     _,-'""`-._
(,-.`._,'(       |\`-/|
    `-.-' \ )-`( , o o)  # Closest approximation I could find to ascii nyan cat
          `-    \`_`"'-
Your part of the flag is:63
Next port: 46473
```
But when we go there we just get this again
```bash
Sorry, No cats here...
``` 
No dice. We need to automate this.

# Solution

Summoning pwntools and re makes the code a breeze. We just hammer the ports till we get a response, then we parse the next port and hammer that one until we get its part of the flag and so on...

```python
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
```
This is how running it looked like during the CTF

![Imgur](https://i.imgur.com/8VvCvOX.png)

# Flag

`InnoCTF{49fe100103cbc466c7ba22c373636a56d}`
