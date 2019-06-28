// --------------------------------------------------
// Application server for Dashboard
// --------------------------------------------------
// Dashboard provides user accounts for your web
// application, and proxies your web application to
// form a single website out of two separate servers.
const bcrypt = require('bcryptjs')
const crypto = require('crypto')

function compareDashboardHash(req, dashboardServer, applicationServerToken) {
  if (!req.headers['x-dashboard-server']) {
    return false
  }
  dashboardServer = dashboardServer || process.env.DASHBOARD_SERVER
  if (req.headers['x-dashboard-server'] !== dashboardServer) {
    return false
  }
  applicationServerToken = applicationServerToken || process.env.APPLICATION_SERVER_TOKEN
  if (!applicationServerToken) {
    return false
  }
  let expected
  if (!req.headers['x-accountid']) {
    expected = applicationServerToken
  } else {
    expected = `${applicationServerToken}/${req.headers['x-accountid']}/${req.headers['x-sessionid']}`
  }
  const sha = crypto.createHash('sha256')
  const expectedHash = sha.update(expected).digest('hex')
  req.dashboardServer = bcrypt.compare(expectedHash, hashedToken, callback)
  if (req.dashboardServer) {
    req.accountid = req.headers['x-accountid']
    req.sessionid
  }
}

module.exports = function (req, res, next) {
  // Dashboard software can be published or imported 
  // to app stores like userappstore.com, to claim
  // ownership a token must be published.  You can
  // authorize multiple app stores, they will each
  // have their own claim process and tokens.
  if (req.url.indexOf('/authorized-app-stores/') === 0) {
    let domain = req.url.substring('/authorized-app-stores/'.length)
    domain = domain.substring(0, domain.lastIndexOf('.txt'))
    let n = 0
    while (true) {
      n++
      if (!process.env[`AUTHORIZE_APP_STORE_${n}`]) {
        break
      }
      if (process.env[`AUTHORIZE_APP_STORE_${n}`] !== `https://${domain}` &&
        process.env[`AUTHORIZE_APP_STORE_${n}`] !== `http://${domain}`) {
        continue
      }
      res.statusCode = 200
      res.setHeader('content-type', 'text/plain')
      return res.end(process.env[`AUTHORIZE_APP_STORE_${n}_TOKEN`])
    }
  }
  // Whenever your Dashboard server requests something the
  // request headers will a contain a signature you can 
  // verify, identifying the user and their session.
  compareDashboardHash(req)
  // When an app store requests something its Dashboard
  // server credentials will be used
  if (!req.dashboardServer) {
    let n = 0
    while (true) {
      n++
      if (!process.env[`AUTHORIZE_APP_STORE_${n}`]) {
        break
      }
      const dashboardServer = process.env[`AUTHORIZE_APP_STORE_${n}`]
      const applicationServerToken = process.env[`APPLICATION_SERVER_${n}_TOKEN`]
      compareDashboardHash(req, dashboardServer, applicationServerToken)
      if (req.dashboardServer) {
        break
      }
    }
    if (!req.dashboardServer) {
      res.statusCode = 404
      return res.end()
    }
  }
  return next()
}
