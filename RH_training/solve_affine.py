from fractions import gcd

m = 256
f = bytearray(open('asdf.bin', 'rb').read())

def affine(a, b, x):
    return (a*x + b) % m
'''
for a in range(m):
    if gcd(a, m) != 1:
        continue
    for b in range(m):
        sig = [affine(a, b, f[0]), affine(a, b, f[1])]
        if sig == [0xff, 0xd8]:
            print 'jpeg found with a={} and b={}'.format(a, b)
        if sig == [0x89, 0x50]:
            print 'png found with a={} and b={}'.format(a, b)
'''

png = bytearray([affine(239, 233, x) for x in list(f)])
open('possible.png', 'wb').write(png)
