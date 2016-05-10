# OAuth Token Endpoint Client for Java #

## Description ##
Client helper for OAuth 2.0 Token endpoint. Supports "Client Credentials" flow with "client_secret", RS256 JWT "client_assertion" and custom grants.

## Features ##
- Client Credentials Grant (2-Legged OAuth)
- "client_secret" authentication
- "private_key_jwt" authentication method as defined in [Assertion Framework for OAuth 2.0 Client Authentication and Authorization Grants](https://tools.ietf.org/html/rfc7521#section-6.2) and [OpenID Connect Core 1.0](http://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication)
- Custom grant support. I.e. for custom assertion grants.
- **Access token caching**. Uses in-memory cache by default. Caching key includes all parameters, so it is safe to use with more than one Authorization Server, credential set or OAuth scope list.

_This library only interacts with token endpoint and receives access_token. It is not designed to be used for flows involving authorization endpoint_

_If you need support for other grant types or authentication methods, please check some other implementations._

## Getting started ##
Install with Maven:
```xml
<dependency>
    <groupId>com.scalepoint</groupId>
    <artifactId>oauth-token-client</artifactId>
    <version>1.0</version>
</dependency>
```

Obtaining access token from token endpoint is as simple as this:

###### private_key_jwt ######

```java
ClientCredentialsGrantTokenClient tokenClient = new ClientCredentialsGrantTokenClient(
                                tokenEndpointUri,
                                new JwtBearerClientAssertionCredentials(
                                    tokenEndpointUri,
                                    clientId,
                                    keyPair
                          ));

String accessToken = tokenClient.getToken("scope1", "scope2");
```

_Check [here](src/test/java/com/scalepoint/oauth_token_client/TestCertificateHelper.java) for how you can load "keyPair" from .jks or .pfx file containing only one certificate and key for test purposes._

###### client_secret ######

```java
ClientCredentialsGrantTokenClient tokenClient = new ClientCredentialsGrantTokenClient(
                                tokenEndpointUri,
                                new ClientSecretCredentials(clientId, clientSecret)
                          );

String accessToken = tokenClient.getToken("scope1", "scope2");
```
