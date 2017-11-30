# Whale AuthProxy
> Whale auth support together with the nginx ingress

## Nginx

Header: HTTP_X_ORIGINAL_URL
Query param: rd=url

## How it works

* Nginx proxies to this server to check auth.
* Returns 200 or 401 based on session auth status.
* If 401 is returned, proxy to the sign in page
* Redirect to gate for auth validation
* Redirects back and updates the session