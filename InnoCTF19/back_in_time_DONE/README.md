# Back in time

- Category: Web
- Rating: Medium

We're given a mostly empty webpage at `http://188.130.155.66:1111/sPgnbTpZuBMxGQBIpEMAkhqDSGAlaybE` with a git logo in the background. checking `http://188.130.155.66:1111/sPgnbTpZuBMxGQBIpEMAkhqDSGAlaybE/.git/` confirms that indeed someone forgot to remove their .git folder from theit production website. 

We start by downloading it using [gitdumper](https://github.com/internetwache/GitTools/tree/master/Dumper), and then we're obviously supposed to dig through the history... Unless someone figured out a way to grep through the entire history of a git repo.

![Imgur](https://i.imgur.com/nutnv2f.png)

tomnomnom has.

# Solution

```bash
$ { find .git/objects/pack/ -name "*.idx"|while read i;do git show-index < "$i"|awk '{print $2}';done;find .git/objects/ -type f|grep -v '/pack/'|awk -F'/' '{print $(NF-1)$NF}'; }|while read o;do git cat-file -p $o;done|grep -E 'InnoCTF'

find: ‘.git/objects/pack/’: No such file or directory
NOT A FLAG wDOwdnQzRGdqXxUJMgiVOraPRGdApUmUInnoCTF{nVBdAdtIqkOUUxFqKpypJIPCLpIQrZwr}NOT A FLAG GJuLumsBvtOzbCMchCMnRxIhcJkWKnyhtree e62734d8c2102bc86f2dde033a975741997d76fe
```

# Flag
`InnoCTF{nVBdAdtIqkOUUxFqKpypJIPCLpIQrZwr}`
