# Electron + Kinde (Authorization Code Flow with PKCE)

This sample shows a **desktop-native** sign-in using your system browser, receiving the callback on a temporary localhost port, exchanging the code for tokens, and storing them securely with OS keychain via **keytar**.

## 1) Kinde setup

1. In Kinde Dashboard, create a **Native** app (or enable "Allow public clients / PKCE").  
2. Note the **Issuer** (e.g., `https://your-tenant.kinde.com`) and **Client ID**.
3. Add an **Allowed Callback URL** pattern that includes loopback for development. For native apps using PKCE, Kinde allows loopback URIs. Use a wildcard-friendly entry such as:
   - `http://127.0.0.1/*`  
   (If Kinde requires an explicit port, add a few you plan to use, e.g. `http://127.0.0.1:53180/callback`)
4. (Optional) Add **Allowed Logout URL**: `http://localhost/`.
5. (Optional) Configure **audience** for your API if you plan to call it from the desktop app.

## 2) Configure the sample

Copy `.env.example` to `.env` and fill it:

```
KINDE_ISSUER_URL=https://your-tenant.kinde.com
KINDE_CLIENT_ID=your-native-client-id
KINDE_AUDIENCE=
KINDE_SCOPES=openid profile email offline
```

> `offline` ensures you receive a `refresh_token` so the app can silently refresh access tokens.

## 3) Install & run

```bash
npm i
npm run dev
```

Click **Sign in**. Your default browser opens Kinde's hosted UI.  
After you authenticate and the page shows "Login successful", close the tab and return to the app.  
Click **Get access token** to see a fresh token retrieved (and automatically refreshed when near expiry).

## 4) Where tokens are stored

Tokens live in your OS credential vault via **keytar** (service: `electron-kinde-pkce-sample`, account: `default`).  
Only the minimal ID token claims are held in memory for display.

## 5) Notes

- This sample intentionally uses the system browser and a loopback redirect for best security and user experience.
- If you need to call your API, use `window.kindeAuth.getAccessToken()` to obtain a valid token first.
- To clear state, click **Log out** (it clears local tokens and opens the Kinde logout URL) or delete the keytar entry.
- CSP in the renderer allows `connect-src https:` so fetches to Kinde/token work if you add such calls from the renderer (not needed here).

## 6) Packaging

Use `electron-builder` or `electron-forge` for production packaging. This sample focuses on sign-in flow; add your preferred packager.
