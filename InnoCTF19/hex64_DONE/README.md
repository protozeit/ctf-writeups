# Hex64

- Category: PPC
- Rating: Easy

We are given a huge file that looks like some base64

```
...YTQ0NjMzNTRlNDc1NTMwNGU0NDU1MzE0ZTMyNDUzMDVhNDQ1NTMwNGU1NDU1N2E0ZTU0NTI2YzRlNTQ1MTMxNGQ1NDRkNzg0ZTQ3NTEzMTRlNDQ1OTdhNGQ3YTUxMzA1YTU0NTEzMzRlNTQ0NTMzNTk1NDUyNmI0ZTZkNDUzMTRlNTQ2MzM0NGU0NzU1N2E0ZDZhNTEzMTRkN2E0NTMxNGY1NDU1MzA0ZTU0NDUzMzRmNDQ1MjZiNGQ3YTQ5MzE0ZDU0NjQ2ODRlNTc0NTMwNGQ1NDRlNmI0ZDMyNTEzZA==
```

```bash
$ base64 -d Hex64 | tail -c 300

526c4e4463314e544d774e4755304e4455314e7a67305a4464684e44557a4d4456684e5451305a4463354e4755304e4455314e3245305a4455304e54557a4e54526c4e5451314d544d784e4751314e44597a4d7a51305a5451334e5445335954526b4e6d45314e5463344e47557a4d6a51314d7a45314f5455304e5445334f44526b4d7a49314d5464684e5745304d544e6b4d32513d
```

After base64 decoding it we get some hex values that are in the printable range, so let's fire up python and see what it says

```python
Python 2.7.15+ (default, Nov 27 2018, 23:36:35)
[GCC 7.3.0] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> c = open('Hex64', 'r').read().decode('base64').decode('hex')
>>> c[-300:]
'NGU2YTY3MzA1YTU0NTUzMDRlNTQ1NTMzNTk1NDUyNmI0ZTQ0NTEzMTRlNmE1OTM0NGU0NzU1MzA0ZTQ0NTU3ODRkN2E0MTMxNTk1NDUxMzA0ZTZhNGQ3YTRlNTQ1MjZjNGU0NDYzMzE0ZTU0NGQ3ODRlNDc1NTMwNGU0NDU1Nzg0ZDdhNDUzMDVhNTQ0ZDc5NGU0NDU1N2E0ZDU0NTUzNTRlNTQ1MTMxNGQ1NDYzMzQ0ZTQ3NTE3YTRkNmE1NTc4NGUzMjQ1MzE1OTU0NTE3ODRkMzI1MTdhNWE0MTNkM2Q='
>>>
```

It looks like more base64 again. We will have to script this.

# Solution

```python
c = open('Hex64', 'r').read()
i = 0
while "InnoCTF" not in c:
    if i % 2 == 0:
        c = c.decode('base64')
    else:
        c = c.decode('hex')
    i += 1
print c
```

# Flag

`InnoCTF{why_s0_larg3}`
