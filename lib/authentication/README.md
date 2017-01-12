lib/authentication
==================

## Design

The authentication package is designed to wrap an underyling storage mechanism, so that it can
be used to authenticate incoming tokens. It expects the storage layer to index secrets with an ID.
This ID should be obtained from the provided JWT token at validation time, within the claim itself.
The key for this claim can be configured at construction time of the Authenticator, using the
`WithIDKey(idKey string)` Option function. Otherwise a default key of `id_key` is used.

## Storage Interface

harry/lib/authentication is only concerned with authenticating challenges, not
creating or managing existing secrets / identities. Therefore, the storage layer
interface required by this package is a simple FetchSecret method for a given
id string.

```go
type Storage interface {
  FetchSecret(id string) (secret Secret, present bool, err error)
}
```
