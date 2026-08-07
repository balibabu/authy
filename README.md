# 🔐 Authenticator

A fast, private, **dark-themed** Time-based One-Time Password (TOTP) app that runs
entirely in your browser. Add your 2FA secret keys once and your codes appear
automatically every time you come back — no servers, no sign-up, no tracking.

> Open [`index.html`](index.html) and you're ready to go.

---

## ✨ Why you'll like it

- **Six-digit TOTP codes** that refresh every 30 seconds — just like Google Authenticator.
- **Remembers your accounts.** Secrets are saved in your browser's `localStorage`, so your codes show up automatically on your next visit.
- **Multiple accounts.** Add as many secrets as you need — each gets its own card.
- **One-tap copy.** Click the copy button to grab a code instantly.
- **Delete anytime.** Remove a single account, or clear everything.
- **Auto-cleanup.** Accounts you haven't used in **7 days** are removed automatically to keep things tidy and private.
- **100% local.** Your secrets never leave your device. No network calls, no analytics.

---

## 🚀 Getting started

1. Download [`index.html`](index.html) and [`app.js`](app.js) into the same folder.
2. Double-click [`index.html`](index.html) to open it in any modern browser.
3. Add your first account:
   - Enter a **Label** (e.g. `GitHub`)
   - Paste your **secret** in Base32 format
   - Click **Add**

That's it — your 6-digit code appears with a live countdown ring. 🎉

> 💡 **Where do I get a secret?** When a site enables 2FA, look for the
> "manual entry" or "can't scan the QR code" option — it shows a string of
> letters and numbers. That's your Base32 secret.

---

## 🧠 How it works

TOTP is an algorithm defined in [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238).
Here's the simple version:

1. **A shared secret** (your Base32 key) is stored locally on your device.
2. **The current time** is divided into 30-second windows. Each window gets a number called a *counter*.
3. **An HMAC-SHA1** signature is computed from the secret + counter.
4. **A 6-digit code** is extracted from that signature via [dynamic truncation](https://datatracker.ietf.org/doc/html/rfc4226) (RFC 4226).

Because the server holds the same secret and the same clock, you both arrive at
the same 6-digit code for the same 30-second window. The code rotates constantly,
which is what makes it secure.

The cryptography here uses the browser's native **WebCrypto API**, and codes are
recomputed live — no code is ever sent anywhere.

---

## 🗂️ Files

| File | Purpose |
|------|---------|
| [`index.html`](index.html) | Dark-themed UI built with TailwindCSS |
| [`app.js`](app.js) | TOTP generation, `localStorage` handling & rendering |

---

## 🔒 Privacy

- Everything runs client-side in your browser.
- Secrets are stored only in `localStorage` on **your** machine.
- Clearing your browser data (or clicking **Clear all**) removes them permanently.
- Nothing is uploaded — there is no backend.

---

## 🧹 Auto-expiry

To protect your privacy, any account you haven't used in **7 days** is
automatically deleted the next time the app loads (or when you return to its tab).
Use an account at least once a week to keep it around.

---

*Built with plain HTML, JavaScript, and TailwindCSS — no build step required.*
