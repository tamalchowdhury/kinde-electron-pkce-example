const loginBtn = document.getElementById('login')
const getTokenBtn = document.getElementById('getToken')
const logoutBtn = document.getElementById('logout')
const claimsPre = document.getElementById('claims')
const tokenPre = document.getElementById('token')

loginBtn.addEventListener('click', async () => {
  claimsPre.textContent = '...'
  const res = await window.kindeAuth.login()
  if (!res.ok) {
    claimsPre.textContent = 'Login failed: ' + res.error
  } else {
    claimsPre.textContent = JSON.stringify(res.claims, null, 2)
  }
})

getTokenBtn.addEventListener('click', async () => {
  tokenPre.textContent = '...'
  const res = await window.kindeAuth.getAccessToken()
  if (!res.ok) tokenPre.textContent = 'Error: ' + res.error
  else tokenPre.textContent = res.access_token || '(no token)'
})

logoutBtn.addEventListener('click', async () => {
  await window.kindeAuth.logout()
  claimsPre.textContent = '{}'
  tokenPre.textContent = '(logged out)'
})
