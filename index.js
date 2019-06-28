// --------------------------------------------------
// Application server for Dashboard
// --------------------------------------------------
// Dashboard provides user accounts for your web
// application, and proxies your web application to
// form a single website out of two separate servers.
const crypto = require('crypto')
  
function compareDashboardHash (hashedToken, accountid, sessionid) {
  let expected
  if (accountid) {
    expected = `${process.env.APPLICATION_SERVER_TOKEN}/${accountid}/${sessionid}`
  } else {
     expected = process.env.APPLICATION_SERVER_TOKEN
  }
  const sha = crypto.createHash('sha256')
  const expectedHash = sha.update(expected).digest('hex')
  return bcrypt.compare(expectedHash, hashedToken, callback)
}

module.exports = function (req, res, next) {
  // Dashboard software can be published or imported 
  // to app stores like userappstore.com, to claim
  // ownership a token must be published.  You can
  // authorize multiple app stores, they will each
  // have their own claim process and tokens.
  if (req.url.indexOf('/authorized-app-stores/') === 0) {
    let domain = req.url.substring('/authorized-app-stores/'.length)
    const q = domain.indexOf('?')
    if (q > -1) {
      domain = domain.substring(0, q)
    }
    let n = 0
    while (true) {
      n++
      if (!process.env[`AUTHORIZE_APP_STORE_${n}`]) {  
        break
      }
      if (process.env[`AUTHORIZE_APP_STORE_${n}`] !== domain) {
        continue
      }
      res.statusCode = 200
      res.setHeader('content-type', 'text/plain')
      return res.end(process.env[`AUTHORIZE_APP_STORE_${n}_TOKEN`])
    }
  }
  // Whenever a Dashboard server requests something the
  // request headers will a contain a signature you can 
  // verify, identifying the user and their session.
  //
  // When imported to, or published on app stores there
  // may also be an organizationid header 
  if (req.headers['x-dashboard-server'] === process.env.DASHBOARD_SERVER) {
    if (!req.headers['x-accountid']) {
      // guest accessing something
      const token = req.headers['x-dashboard-token']
      req.dashboardServer = compareDashboardHash(token)
    } else {
      // user is signed in
      const token = req.headers['x-dashboard-token']
      const accountid = req.headers['x-accountid']
      const sessionid = req.headers['x-sessionid']
      req.dashboardServer = compareDashboardHash(token, accountid, sessionid)
      if (req.dashboardServer) {
        req.dashboardServer = true
        req.accountid = accountid
        req.sessionid = sessionid
      }
    }
  }
  if (!req.dashboardServer) {
    res.statusCode = 404
    return res.end()
  }
  return next()
}
