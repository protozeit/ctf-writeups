from math import gcd

data = bytearray(open('zakukozh.bin', 'rb').read())
m = 256

def affine(n, a, b):
    return (a*n + b) % m

for a in range(m):
    if gcd(a, m) != 1:
        continue
    for b in range(m):
        new = [affine(data[0],a,b), affine(data[1],a,b)]
        if new == [255, 216]:
            print("possible jpg:",a,b)
        if new == [137,80]:
            print("possible png:",a,b)

# possible jpg: 177 159
# possible png: 239 233

jpg = bytearray([affine(b,177,159) for b in list(data)])
png = bytearray([affine(b,239,233) for b in list(data)])
open('out.jpg','wb').write(jpg)
open('out.png','wb').write(png)
