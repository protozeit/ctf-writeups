from itertools import product
from string import ascii_lowercase
import random

m = open('he_got_it.txt').read()
alphabet = [''.join(a) for a in list(product(['a','b','c','d','e'], ['1','2','3','4','5']))]
random.shuffle(alphabet)

# print 'using permutation: ' + str(alphabet)

translation_dict = {a: b for a,b in zip(list(ascii_lowercase.strip('j')), alphabet)}
translation_dict['j'] = translation_dict['i']

for r in translation_dict.keys():
    m = m.replace(r, translation_dict[r].capitalize())

print m
