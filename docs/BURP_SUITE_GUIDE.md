# Burp Suite Community Edition: quick start for this project

Burp Suite sits between your browser and the portal so you can see and change every request. Use it **only** against `127.0.0.1` on your own computer.

## What Community Edition can and cannot do

| Tool | In Community Edition |
|---|---|
| Proxy (intercept, HTTP history) | Yes |
| Repeater (resend and edit one request) | Yes |
| Decoder, Comparer | Yes |
| Intruder | Yes, but rate-limited (slow). Fine for small tests |
| Scanner (automatic vulnerability scanning) | **No** (Professional only). All testing here is manual |
| Saving projects | No (temporary projects only). Export evidence yourself |

## Setup (easiest way: Burp's built-in browser)

1. Start the portal (`python app.py`) and open Burp Suite. Choose **Temporary project**, then **Use Burp defaults**.
2. Go to **Proxy > Intercept** and click **Open browser**. This browser is already configured to use Burp.
3. In that browser open `http://127.0.0.1:5000`.
4. Turn **Intercept off** (button says "Intercept is off") so pages load normally. Everything still appears in **Proxy > HTTP history**.
5. Use the portal normally, then study the requests in HTTP history. Right-click a request and choose **Send to Repeater** to change and resend it.

## Using your own browser instead

1. In Burp: **Proxy > Proxy settings**, confirm a listener on `127.0.0.1:8080`.
2. Set your browser's proxy to `127.0.0.1` port `8080`.
3. **Common problem:** Chrome and Edge skip the proxy for `localhost` and `127.0.0.1`, so nothing shows in Burp. Firefox has a similar rule. Fix by using Burp's built-in browser (recommended), or in Firefox set `network.proxy.allow_hijacking_localhost` to `true` in `about:config`.
4. For HTTPS sites you would install Burp's CA certificate. You do not need that here because the portal uses plain `http://` locally.

## Habits that make your report credible

- Test with at least **two student accounts** and one admin account, so you can try to reach one user's data from another.
- Change one thing at a time in Repeater and write down the exact request and response.
- Save evidence: right-click a request in Burp and choose **Copy URL / Save item**, and take screenshots.
- The CSRF token changes with every session. If a replayed POST returns **400**, fetch a fresh page, copy the new `csrf_token`, and try again. That 400 is the protection working, and it is worth documenting.
- Throttling: after 5 failed logins for a username the app returns **429**. Wait 15 minutes, or use a different username, before continuing.
