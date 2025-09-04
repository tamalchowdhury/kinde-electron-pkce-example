// main.js (CommonJS) — Fix A: single Express listener on a fixed port
require("dotenv").config()

const { app, BrowserWindow, ipcMain, shell } = require("electron")
const path = require("path")
const os = require("os")
const express = require("express")
const keytar = require("keytar")
const crypto = require("crypto")
const Store = require("electron-store")

// Use a fixed port (add this exact URL in Kinde Allowed Callback URLs)
const CALLBACK_PORT = 53180

const ISSUER = process.env.KINDE_ISSUER_URL
const CLIENT_ID = process.env.KINDE_CLIENT_ID
const AUDIENCE = process.env.KINDE_AUDIENCE || ""
const SCOPES = (
  process.env.KINDE_SCOPES || "openid profile email offline"
).trim()

if (!ISSUER || !CLIENT_ID) {
  console.error("Please configure KINDE_ISSUER_URL and KINDE_CLIENT_ID in .env")
}

const SERVICE_NAME = "electron-kinde-pkce-sample"
const ACCOUNT_NAME = os.userInfo().username

const store = new Store({ name: "app-prefs" }) // not used yet, but kept if you need it

// Ensure fetch exists (Electron/Node 18+ has it; fallback to node-fetch if needed)
const fetchFn =
  global.fetch ||
  ((...args) => import("node-fetch").then(({ default: f }) => f(...args)))

// ---------- PKCE helpers ----------
function base64urlencode(buf) {
  return buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "")
}
function generateVerifier() {
  return base64urlencode(crypto.randomBytes(32))
}
function challengeFromVerifier(v) {
  return base64urlencode(crypto.createHash("sha256").update(v).digest())
}

function randomState(len = 12) {
  return crypto
    .randomBytes(Math.ceil((len * 3) / 4))
    .toString("base64url")
    .slice(0, len)
}

// Minimal JWT decode (no signature verification)
function decodeIdToken(idToken) {
  try {
    const [, payload] = idToken.split(".")
    const pad = (s) => s + "=".repeat((4 - (s.length % 4)) % 4)
    const json = Buffer.from(
      pad(payload).replace(/-/g, "+").replace(/_/g, "/"),
      "base64"
    ).toString("utf8")
    return JSON.parse(json)
  } catch {
    return null
  }
}

// ---------- Token storage ----------
async function saveTokens(tokens) {
  const payload = JSON.stringify({
    access_token: tokens.access_token,
    refresh_token: tokens.refresh_token,
    id_token: tokens.id_token,
    issued_at: Date.now(),
    expires_in: tokens.expires_in,
    token_type: tokens.token_type,
    scope: tokens.scope,
  })
  await keytar.setPassword(SERVICE_NAME, ACCOUNT_NAME, payload)
}
async function loadTokens() {
  const payload = await keytar.getPassword(SERVICE_NAME, ACCOUNT_NAME)
  return payload ? JSON.parse(payload) : null
}
async function clearTokens() {
  await keytar.deletePassword(SERVICE_NAME, ACCOUNT_NAME)
}

// ---------- OAuth helpers ----------
async function exchangeCodeForTokens({ code, codeVerifier, redirectUri }) {
  const tokenUrl = new URL("/oauth2/token", ISSUER).toString()
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    client_id: CLIENT_ID,
    redirect_uri: redirectUri,
    code_verifier: codeVerifier,
  })
  const res = await fetchFn(tokenUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  })
  if (!res.ok)
    throw new Error(`Token exchange failed: ${res.status} ${await res.text()}`)
  return await res.json()
}

async function refreshTokens(refreshToken) {
  const tokenUrl = new URL("/oauth2/token", ISSUER).toString()
  const body = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: refreshToken,
    client_id: CLIENT_ID,
  })
  const res = await fetchFn(tokenUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  })
  if (!res.ok)
    throw new Error(`Refresh failed: ${res.status} ${await res.text()}`)
  return await res.json()
}

async function getValidAccessToken() {
  const tokens = await loadTokens()
  if (!tokens) return null

  const ageMs = Date.now() - (tokens.issued_at || 0)
  const expiresMs = (tokens.expires_in || 0) * 1000
  const aboutToExpire = ageMs > expiresMs - 60_000 // refresh if <60s left
  if (!aboutToExpire) return tokens.access_token

  if (!tokens.refresh_token) return null
  const refreshed = await refreshTokens(tokens.refresh_token)
  await saveTokens(refreshed)
  return refreshed.access_token
}

// ---------- Callback server (single fixed port) ----------
function listenForCallback() {
  const appx = express()
  const redirectUri = `http://127.0.0.1:${CALLBACK_PORT}/callback`

  let resolveLogin
  let rejectLogin
  const waitForCode = new Promise((resolve, reject) => {
    resolveLogin = resolve
    rejectLogin = reject
  })

  appx.get("/callback", async (req, res) => {
    const { code, error, error_description } = req.query
    if (error) {
      res
        .status(400)
        .send(`<h1>Login error</h1><p>${error}: ${error_description || ""}</p>`)
      rejectLogin(new Error(`${error}: ${error_description || ""}`))
      return
    }
    res.send(
      "<h1>Login successful</h1><p>You can close this window and return to the app.</p>"
    )
    resolveLogin({ code: String(code), redirectUri })
    // Do NOT close the server here; we never started it as a variable in this scope.
    // The listener will keep running for future sign-ins unless you manage lifecycle externally.
  })

  const server = appx.listen(CALLBACK_PORT, "127.0.0.1")
  server.on("error", (err) => {
    if (err && err.code === "EADDRINUSE") {
      rejectLogin(
        new Error(
          `Callback port ${CALLBACK_PORT} is already in use. Close the other process or change the port.`
        )
      )
    } else {
      rejectLogin(err)
    }
  })

  // Return the promise and a way to close the server after we get a code
  return { waitForCode, close: () => server.close() }
}

// ---------- Login flow ----------
async function startLogin() {
  const v = generateVerifier()
  const codeVerifier = v
  const codeChallenge = challengeFromVerifier(v)
  const state = randomState()

  // Start single fixed-port server, no extra listeners anywhere else
  const { waitForCode, close } = listenForCallback()
  const redirectUri = `http://127.0.0.1:${CALLBACK_PORT}/callback`

  const auth = new URL("/oauth2/auth", ISSUER)
  auth.searchParams.set("client_id", CLIENT_ID)
  auth.searchParams.set("response_type", "code")
  auth.searchParams.set("redirect_uri", redirectUri)
  auth.searchParams.set("scope", SCOPES)
  auth.searchParams.set("code_challenge_method", "S256")
  auth.searchParams.set("code_challenge", codeChallenge)
  auth.searchParams.set("state", state)
  if (AUDIENCE) auth.searchParams.set("audience", AUDIENCE)

  await shell.openExternal(auth.toString())

  const { code } = await waitForCode
  // Close the callback server once we have the code
  try {
    close()
  } catch {}

  const tokens = await exchangeCodeForTokens({
    code,
    codeVerifier,
    redirectUri,
  })
  await saveTokens(tokens)
  const claims = decodeIdToken(tokens.id_token)
  return { tokens, claims }
}

async function doLogout() {
  await clearTokens()
  try {
    const url = new URL("/logout", ISSUER)
    url.searchParams.set("client_id", CLIENT_ID)
    await shell.openExternal(url.toString())
  } catch {}
}

// ---------- Electron window ----------
let win
function createWindow() {
  win = new BrowserWindow({
    width: 1000,
    height: 700,
    webPreferences: {
      preload: path.join(__dirname, "preload.js"), // keep your CommonJS preload
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  })
  win.loadFile(path.join(__dirname, "renderer", "index.html"))
}

app.whenReady().then(() => {
  createWindow()
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow()
  })
})

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit()
})

// ---------- IPC ----------
ipcMain.handle("auth:login", async () => {
  try {
    const { claims } = await startLogin()
    return { ok: true, claims }
  } catch (e) {
    return { ok: false, error: String(e) }
  }
})

ipcMain.handle("auth:getAccessToken", async () => {
  try {
    const token = await getValidAccessToken()
    return { ok: true, access_token: token }
  } catch (e) {
    return { ok: false, error: String(e) }
  }
})

ipcMain.handle("auth:logout", async () => {
  try {
    await doLogout()
    return { ok: true }
  } catch (e) {
    return { ok: false, error: String(e) }
  }
})

ipcMain.handle("auth:getSession", async () => {
  try {
    const tokens = await loadTokens()
    if (!tokens) return { ok: true, signedIn: false }

    // Optionally ensure access token is fresh (also proves the session is valid)
    const access_token = await getValidAccessToken().catch(() => null)
    const claims = decodeIdToken(tokens.id_token)

    return { ok: true, signedIn: true, claims, access_token }
  } catch (e) {
    return { ok: false, error: String(e) }
  }
})
