hola - JWT authorization toolkit
================================

Simple micro-service toolkit which uses JWT to provide OpenID style authentication components.


## Components

`github.com/georgemac/hola/lib/identity`

> Identity primitives and storage interface

This package defines the Identity "primitive", which encapsulates a key, a secret, a set of scopes and a signature method.
The package also contains an interface which models a mechanism for secret storage and retrieval. The identity.Storage interfaces
describes what is required to be exposed by a storage layer, in order for it to be useful within a `hola` authentication flow.

`github.com/georgemac/hola/lib/authentication`

> Simple secret retrieval and verification flow

The authentication package exposes an Authenticator type, which wraps an `identity.Storage` and implements
a simple token retrieval, verification and scope verification flow. It uses the tokens ISS claim as a key for the storage implementation.

`github.com/georgemac/hola/lib/middleware`

> A set of transport middleware which use the simple `hola` authentication flow.

- `middleware.HTTP` is an implementation of `http.Handler` which decorates another implementation of `http.Handler`. It parses a JWT token from the request and then fetches an associated identity using an embedded `authentication.Authenticator`. If the token and its scope claims are verified, the scopes are bundled in to the requests context.Context and the underlying `http.Handler` is called. Otherwise, an appropriate http status code is formed from the error type and the middleware returns.
