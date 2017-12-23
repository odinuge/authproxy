# Whale AuthProxy
> OpenID Connect auth proxy for NGINX with additional Whale permission check.

This service requires the X-ORIGINAL-URL header and rd query parameter that exists in
newer versions of the nginx ingress service.

## Configuration

* cookieName - The name of the cookie used to store the session
* cookieSecret - Secret key used to generate the session
* oidcClientID - Client ID
* oidcClientSecret - Client secret
* oidcIssuer - The OpenID connect provider service. Defaults to (https://gate.whale.io)
* whalePermissions - Enables an extra permission check using the Whale API. The issuer
  needs to be Whale Gate when you enables this feature.

## Todo

* Tracing Support
* Prometheus monitoring, requests, status codes and content-type
* Store a random assigned value in the state parameter, this requires a datastore
  because is't normal to run multiple proxy instances.
