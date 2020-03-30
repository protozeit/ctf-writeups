# Eternal game

- Category: crypto
- Rating: ? pts

> No one has ever won my game except me!
> nc challenges.tamuctf.com 8812

We connect to the challenge and this is what we get

```
1. New Game
2. Claim Prize
3. Exit
1

            Welcome the The Game. You are allowed to multiply the initial number (which is 1) by any
            number in the range 2-10. Make decisions wisely! You can only multiply by each
            number at most 5 times... so be careful. Also, at a random point during The Game, an asteroid
            will impact the Earth and The Game will be over.

            Feel free to get your proof of achievement and claim your prize at the main menu once
            you start reaching big numbers. Bet you can't beat my high score!
```
Okay big boi let's see whatchu got

```         
1. Multiply
2. Print current value
3. Get proof and quit
1
Multiplier: 
9
1. Multiply
2. Print current value
3. Get proof and quit
1
Multiplier: 
9
1. Multiply
2. Print current value
3. Get proof and quit
2
81
```

Okayy fair enough `9 x 9 = 81`, let's see how the proof looks like

```
1. Multiply
2. Print current value
3. Get proof and quit
3
3b66180f42e875f434dd4c1f6a3a17af91c9e15d7e55866d660a524b515009e759d0f58bcf8d9d60115d2d83c9f59b8cf5151dac5f797afe4d9bcc66d3c2115e
```

let's go claim our prize c:
```
1. New Game
2. Claim Prize
3. Exit
2
Input the number you reached: 
81
Present the proof of your achievement: 
3b66180f42e875f434dd4c1f6a3a17af91c9e15d7e55866d660a524b515009e759d0f58bcf8d9d60115d2d83c9f59b8cf5151dac5f797afe4d9bcc66d3c2115e
You can do better than that.
```
Really... let's check out this guy's high score

```python
from collections import defaultdict
import random
import hashlib
import sys

x = 1
d = defaultdict(int)
game_running = True
high_score = 653086069891774904466108141306028536722619133804

def gen_hash(x):
    with open('key.txt', 'r') as f:
        key = f.read()[:-1]
        return hashlib.sha512(key + x).hexdigest()

def extract_int(s):
    i = len(s)-1
    result = 0
    while i >= 0 and s[i].isdigit():
        result *= 10
        result += ord(s[i]) - ord('0')
        i -= 1
    return result

def multiply():
    global x
    print 'Multiplier: '
    sys.stdout.flush()
    m = extract_int(raw_input())
    sys.stdout.flush()
    if m < 2 or m > 10:
        print 'Disallowed value.'
    elif d[m] == 5:
        print 'You already multiplied by ' + str(m) + ' five times!'
    else:
        x *= m
        d[m] += 1
    sys.stdout.flush()

def print_value():
    print x
    sys.stdout.flush()

def get_proof():
    global game_running
    game_running = False
    print gen_hash(str(x))
    sys.stdout.flush()

game_options = [multiply, print_value, get_proof]
def play_game():
    global game_running
    game_running = True
    print(
            '''
            Welcome the The Game. You are allowed to multiply the initial number (which is 1) by any
            number in the range 2-10. Make decisions wisely! You can only multiply by each
            number at most 5 times... so be careful. Also, at a random point during The Game, an asteroid
            will impact the Earth and The Game will be over.

            Feel free to get your proof of achievement and claim your prize at the main menu once
            you start reaching big numbers. Bet you can't beat my high score!
            '''
            )
    while game_running:
        print '1. Multiply'
        print '2. Print current value'
        print '3. Get proof and quit'
        sys.stdout.flush()
        game_options[extract_int(raw_input())-1]()
        sys.stdout.flush()
        if random.randint(1, 20) == 10:
            print 'ASTEROID!'
            game_running = False
        sys.stdout.flush()

def prize():
    print 'Input the number you reached: '
    sys.stdout.flush()
    num = raw_input()
    sys.stdout.flush()
    print 'Present the proof of your achievement: '
    sys.stdout.flush()
    proof = raw_input()
    sys.stdout.flush()
    num_hash = gen_hash(num)
    num = extract_int(num)

    if proof == num_hash:
        if num > high_score:
            with open('flag.txt', 'r') as f:
                print f.read()
        elif num > 10**18:
            print 'It sure is a good thing I wrote this in Python. Incredible!'
        elif num > 10**9:
            print 'This is becoming ridiculous... almost out of bounds on a 32 bit integer!'
        elif num > 10**6:
            print 'Into the millions!'
        elif num > 1000:
            print 'Good start!'
        else:
            print 'You can do better than that.'
    else:
        print 'Don\'t play games with me. I told you you couldn\'t beat my high score, so why are you even trying?'
    sys.stdout.flush()

def new():
    global x
    global d
    x = 1
    d = defaultdict(int)
    sys.stdout.flush()
    play_game()

main_options = [new, prize, exit]

def main_menu():
    print '1. New Game'
    print '2. Claim Prize'
    print '3. Exit'
    sys.stdout.flush()
    main_options[extract_int(raw_input())-1]()
    sys.stdout.flush()

if __name__ == '__main__':
    while True:
        main_menu()
```

Obviously this is cheating because `653086069891774904466108141306028536722619133804` is unreachable within the rules. Time to play dirty...

First let's checkout `extract_int` which sanitizes our input

```
>>> extract_int('asdf')
0
>>> extract_int('10**100')
1
>>> extract_int('10100')
101
>>> extract_int('1')
1
>>> extract_int('10')
1
>>> extract_int('14893')
39841
```

It seems that it's doing its job correctly with the weird side effect of reversing the value. But this doesn't really mean much since only values between `2` and `10` are allowed. Let's keep this in mind...

```
if m < 2 or m > 10:
	print 'Disallowed value.'
```

The proof is just `sha512(key || score)`. sha512 belongs to the SHA-2 family of hash function which are vulnerable to [length extension attacks](https://en.wikipedia.org/wiki/Length_extension_attack)

That means that, even though we don't know the key, given `sha512(key || x)` we can calculate `sha512(key || x || y)` for any y (as far as I know), but we do need the length of the key. But that we can just brute force.

# Solution

Plan: we forge a proof for `1 + 653086069891774904466108141306028536722619133804`.

Note, because of how `extract_int` reverses the numbers, we will need to reverse our score too.

We will use [hashpump](https://github.com/bwall/HashPump) to do the hash extension.


```python
#!/usr/bin/env python

from pwn import *
import hashpumpy

r = remote("challenges.tamuctf.com", 8812)
# r = process(["python2", "game.py"])

# context.log_level = 'DEBUG'

proof_for_6 = "1ec356a3f23437e5350a1288a270bf221af33ec1c8b7d5147738e532534fb0b1ee5678e1cbba120b27b1d20c3ac5c2479be7b139b9181ead93fc841a50f8237b"
score = "653086069891774904466108141306028536722619133805"

def claim_prize(score, proof):
    r.sendlineafter("3. Exit", '2')
    r.sendlineafter("Input the number you reached:", score)
    r.sendlineafter("Present the proof of your achievement:", proof)
    r.recvline()
    return r.recvline()

for l in range(1,256):
    print("trying with key of length %d" % l)
    res = hashpumpy.hashpump(proof_for_6, score[0], score[::-1], l) 
    x = claim_prize(res[1], res[0])
    if b"Don't play games with me" in x:
        continue
    else:
        print(x)
        break

r.interactive()
```
# Flag

`gigem{a11_uR_h4sH_rR_be10nG_to_m3Ee3}`
