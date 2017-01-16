package identity

import (
	"gopkg.in/jose.v1/crypto"
	"gopkg.in/jose.v1/jwt"
)

// validate at compile time that StorageFunc implements Storage.
var _ Storage = StorageFunc(nil)

// Identity is a struct which contains a secret used
// to decode a token and the relevant signing mechanism
// used to encode it in the first place.
type Identity struct {
	Key    string
	Secret []byte
	Scopes []string
	Method crypto.SigningMethod
}

// Validate calls validate on the JWT token with
// the data and method embedded within the struct.
func (i Identity) Validate(token jwt.JWT) error {
	return token.Validate(i.Secret, i.Method)
}

// Storage is an interface which describes the methods required
// by the authentication package to be present in order to
// perform its authentication duties.
type Storage interface {
	FetchIdentity(key string) (identity Identity, ok bool, err error)
}

// StorageFunc implements the Storage interface.
// This allows for simple functions to be used as Storage layers.
type StorageFunc func(string) (Identity, bool, error)

// FetchIdentity takes and key string and returns the associated identity,
// If the identity is not present the returned boolean WILL BE FALSE.
// If something else went wrong during the fetch process err WILL NOT BE NIL.
func (s StorageFunc) FetchIdentity(key string) (Identity, bool, error) {
	return s(key)
}
