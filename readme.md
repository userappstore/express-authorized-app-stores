# Express middleware for application servers

This middleware verifies requests come from your Dashboard server, and authorizes app stores to publish/import your server.

## When to use this

You are integrating Dashboard with your existing or new NodeJS project using Express.

## What it does

When claiming an application server on [UserAppStore](https://userappstore.com) or other sites powered by our [app store software](https://github.com/userappstore/app-store-dashboard-server) you must publish a token on your application server.  Claiming the server enables you to administrate your users on that app store, or publish it as free or paid subscription software.  You will be given the token during the claiming process on each app store.

The first thing this middleware does is provide those tokens configured via numbered ENV variables.  This middleware iterates 1 through however it many it finds, stopping when _x is unconfigured.

    AUTHORIZE_APP_STORE_1=userappstore.com
    AUTHORIZE_APP_STORE_1_TOKEN=token
    ..
    AUTHORIZE_APP_STORE_23=something-something-something.com
    AUTHORIZE_APP_STORE_23_TOKEN=another-token

The second and final thing this middleware does is verify that requests come from your Dashboard server or an app store.  This is done using a shared secret `APPLICATION_SERVER_TOKEN` that you define when running your own website with Dashboard.  On app stores this token is provided for you and can be rotated at any time you desire.  Requests are signed with that token along with the user's account and session identifiers if signed in, and this middleware verifies that the signature matches.

## The end result

If the signature verification fails the request will be marked as 404 and end with an empty response.

If the signature verification passes the request will proceed and these properties will be set on the `req` object:

    req.dashboardServer = true
    req.accountid = req.headers['x-accountid']
    req.sessionid = req.headers['x-sessionid']