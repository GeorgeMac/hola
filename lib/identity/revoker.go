package identity

// validate at compile time that RevokerFunc implements Revoker.
var _ Revoker = RevokerFunc(nil)

// Revoker is an interface which describes the methods required
// by a storage mechanism to revoke an identity for a given key
type Revoker interface {
	Revoke(key string) error
}

// RevokerFunc implements the Revoker interface.
// This allows for simple functions to be used as Revoker layers.
type RevokerFunc func(string) error

// Revoke takes a key string and revokes the associated identity.
func (r RevokerFunc) Revoke(key string) error {
	return r(key)
}
