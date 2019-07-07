# Clumsy developer

- Level: medium
- Points: 100
- Category: RE

The decrypt function simply increments each of the characters of the hard coded string "Gdkkn" into "Hello",
doing the same for the string after the null byte yeilds the flag.


```assembly
...
mov     byte ptr [rbp+var_26], 47h ; 'G'
mov     byte ptr [rbp+var_26+1], 64h ; 'd'
mov     byte ptr [rbp+var_26+2], 6Bh ; 'k'
mov     byte ptr [rbp+var_26+3], 6Bh ; 'k'
mov     byte ptr [rbp+var_26+4], 6Eh ; 'n'
mov     byte ptr [rbp+var_26+5], 0
mov     byte ptr [rbp+var_26+6], 45h ; 'E'
mov     byte ptr [rbp+var_26+7], 4Bh ; 'K'
mov     [rbp+var_1E], 40h ; '@'
mov     [rbp+var_1D], 46h ; 'F'
mov     [rbp+var_1C], 7Ah ; 'z'
mov     [rbp+var_1B], 48h ; 'H'
mov     [rbp+var_1A], 5Eh ; '^'
mov     [rbp+var_19], 42h ; 'B'
mov     [rbp+var_18], 40h ; '@'
mov     [rbp+var_17], 4Dh ; 'M'
mov     [rbp+var_16], 5Eh ; '^'
mov     [rbp+var_15], 40h ; '@'
mov     [rbp+var_14], 43h ; 'C'
mov     [rbp+var_13], 43h ; 'C'
mov     [rbp+var_12], 7Ch ; '|'
mov     [rbp+var_11], 0
lea     rax, [rbp+var_26]
mov     rdi, rax
call    decrypt
lea     rax, [rbp+var_26]
mov     rsi, rax
lea     rdi, format     ; "I should print the flag but I always mi"...
mov     eax, 0
call    _printf
...
```
# Solution

```python3
a = 'EK@FzH^B@M^@CC|'

for i in range(len(a)):
    print(chr(ord(a[i])+1), end='')
```
# Flag

`FLAG{I_CAN_ADD}`
