# Whale AuthProxy
> OpenID Connect auth proxy for NGINX with additional Whale permission check.

## Configuration

* cookieName - The name of the cookie used to store the session
* cookieSecret - Secret key used to generate the session
* oidcClientID - Client ID
* oidcClientSecret - Client secret
* oidcIssuer - The OpenID connect provider service. Defaults to (https://gate.whale.oi)
* whalePermissions - Enables an extra permission check using the Whale API. The issuer
  needs to be Whale Gate when you enables this feature.

## Todo

* Tracing Support
* Prometheus monitoring, requests, status codes and content-type
* Logging