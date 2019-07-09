const bcrypt = require('bcryptjs')
const crypto = require('crypto')

function compareDashboardHash(req, dashboardServer, applicationServerToken, callback) {
  if (!callback && applicationServerToken) {
    callback = applicationServerToken
    applicationServerToken = null
  } else if (!callback && dashboardServer) {
    callback = dashboardServer
    dashboardServer = null
    applicationServerToken = null
  }
  if (!req.headers['x-dashboard-server']) {
    return callback(null, req)
  }
  dashboardServer = dashboardServer || process.env.DASHBOARD_SERVER
  if (!dashboardServer) {
    return callback(null, req)
  }
  if (req.headers['x-dashboard-server'] !== dashboardServer) {
    return callback(null, req)
  }
  applicationServerToken = applicationServerToken || process.env.APPLICATION_SERVER_TOKEN
  if (!applicationServerToken) {
    return callback(null, req)
  }
  let expected
  if (!req.headers['x-accountid']) {
    expected = applicationServerToken
  } else {
    expected = `${applicationServerToken}/${req.headers['x-accountid']}/${req.headers['x-sessionid']}`
  }
  const sha = crypto.createHash('sha256')
  const expectedHash = sha.update(expected).digest('hex')
  return bcrypt.compare(expectedHash, req.headers['x-dashboard-token'], (error, match) => {
    if (match) {
      req.verified = true
      req.dashboard = req.headers[['x-dashboard-server']]
      for (const key in req.headers) {
        if (!key.startsWith('x-') || !key.endsWith('id')) {
          continue
        }
        let name = key.substring(2)
        if (name.indexOf('-') > -1) {
          const nameParts = name.split('-')
          name = ''
          for (const part in nameParts) {
            if (name) {
              name += part.substring(0, 1).toUpperCase() + part.substring(1)
            } else {
              name = part
            }
          }
        }
        req[name] = req.headers[key]
      }
    }
    return callback(null, req)
  })
}

module.exports = (req, res, next) => {
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
      res.end(process.env[`AUTHORIZE_APP_STORE_${n}_TOKEN`])
      return next()
    }
  }
  if (!req.headers['x-dashboard-server']) {
    return next()
  }
  let n = 0
  while (true) {
    n++
    if (!process.env[`PROHIBIT_APP_STORE_${n}`]) {
      break
    }
    if (process.env[`PROHIBIT_APP_STORE_${n}`] === `${req.dashboard}`) {
      return next()
    }
  }
  return compareDashboardHash(req, (_, req) => {
    // When an app store requests something its Dashboard
    // server credentials will be used
    if (req.dashboardServer) {
      return next()
    }
    function nextAppStore(n) {
      if (!process.env[`AUTHORIZE_APP_STORE_${n}`]) {
        return next()
      }
      const dashboardServer = process.env[`AUTHORIZE_APP_STORE_${n}`]
      const applicationServerToken = process.env[`APPLICATION_SERVER_${n}_TOKEN`]
      return compareDashboardHash(req, dashboardServer, applicationServerToken, (_, req) => {
        if (req.dashboardServer) {
          return next()
        }
        return nextAppStore(n + 1)
      })
    }
    return nextAppStore(1)
  })
}
