# One hundred times RSA

- Category: Crypto
- Rating: Easy

This is an RSA where we're given the message `c` and modulus `n` which is pretty small in size

```
c = 603698176784356534065626570171027820554301097275556640590608004001323036552071482035740091533040756
n = 1522605027922533360535618378132637429718068114961380688657908494580122963258952897654000350692006139
```
We can probably factor out the `n` into `p` and `q` using [factordb](factordb.com)
```
p = 37975227936943673922808872755445627854565536638199 
q = 40094690950920881030683735292761468389214899724061
```

Now we only need `e`, which might be brute forcable.

# Solution

```python
from Crypto.Util.number import inverse
import re

# factor n, guess e
c = 603698176784356534065626570171027820554301097275556640590608004001323036552071482035740091533040756
n = 1522605027922533360535618378132637429718068114961380688657908494580122963258952897654000350692006139

p = 37975227936943673922808872755445627854565536638199 # factordb
q = 40094690950920881030683735292761468389214899724061

phi = (q-1) * (p-1)

for e in xrange(0x100000):
    try:
        d = inverse(e, phi)
        m = pow(c, d, n)
        out = hex(m)[2:-1].decode('hex')
        print re.findall('InnoCTF{.*}', out)[0]
        print "e =",e
        break
    except:
        pass
```
This is what it looked like during the competition, it only took about 30 seconds on my pc.

![Imgur](https://i.imgur.com/Xmgby1R.png)

# Flag

`InnoCTF{cr4ck_rs4_4g41n_0faa}`
