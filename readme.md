# Express middleware for authorizing app stores

This middleware verifies requests come either from your Dashboard server or authorized app stores.

## When to use this

You are publishing your web application on [UserAppStore](https://userappstore.com) or another website using our [app store software](https://github.com/userappstore/app-store-application-server).

## What it does

When claiming an application server on [UserAppStore](https://userappstore.com) or other sites powered by our [app store software](https://github.com/userappstore/app-store-dashboard-server) you must verify you own the server by publishing a token.  This module publishes your tokens and verifies requests come from the app stores you ahve approved.  This middleware iterates 1 through however it many it finds, stopping when _x is unconfigured, so you can approve as many app stores as you wish.

    AUTHORIZE_APP_STORE_1=userappstore.com
    AUTHORIZE_APP_STORE_1_TOKEN=token
    ..
    AUTHORIZE_APP_STORE_23=something-something-something.com
    AUTHORIZE_APP_STORE_23_TOKEN=another-token

This middleware can also determine if the request came from your own [Dashboard](https://github.com/userdashboard/dashboard.git) server, in case you are servicing both app stores and your own users directly.

    DASHBOARD_SERVER=http://localhost:8000
    APPLICATION_SERVER_TOKEN="shared secret"

## The end result

If the request came from a recognized app store or your own Dashboard server these properties will be appended to the `request` object:

    req.verified = true
    req.dashboardServer = "https://yours_or_app_store"
    req.accountid = ""
    req.sessionid = ""
    // if the user installed for organizations
    req.organizationid = ""
    // if the user installed via app store
    req.subscriptionid = ""

The integrity of the information can only be confirmed if you claim your application server on the app stores.

#### Development

Development takes place on [Github](https://github.com/userdashboard/express-application-server) with releases on [NPM](https://www.npmjs.com/package/@userdashboard/express-application-server).

#### License

This is free and unencumbered software released into the public domain.  The MIT License is provided for countries that have not established a public domain.