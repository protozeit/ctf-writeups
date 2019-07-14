c = open('Hex64', 'r').read()
i = 0
while "InnoCTF" not in c:
    if i % 2 == 0:
        c = c.decode('base64')
    else:
        c = c.decode('hex')
    i += 1
print c
