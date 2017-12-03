# Whale AuthProxy
> Whale auth support together with the NGINX ingress

## Configuration

## Todo

* Verify that the user has access to the requested resource
* Tracing Support
* Prometheus monitoring, requests, status codes and content-type

## NGINX

* X-ORIGINAL-URL
* ?rd=url

## How it works

* NGINX proxies to this server to check auth
* Returns 200 or 401 based on session status
* If 401 is returned, proxy to the sign in page
* Sign in with a JWT token issued by DEX