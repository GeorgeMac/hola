package authentication

import (
	"gopkg.in/jose.v1/crypto"
	"gopkg.in/jose.v1/jwt"
)

// validate at compile time, that StorageFunc implements Storage.
var _ Storage = StorageFunc(nil)

// Secret is a struct which contains a secret used
// to decode a token and the relevant signing mechanism
// used to encode it in the first place.
type Secret struct {
	Data   []byte
	Method crypto.SigningMethod
}

// Validate calls validate on the JWT token with
// the data and method embedded within the struct.
func (s Secret) Validate(token jwt.JWT) error {
	return token.Validate(s.Data, s.Method)
}

// Storage is an interface which describes the methods required
// by the authentication package to be present in order to
// perform its authentication duties.
type Storage interface {
	FetchSecret(id string) (secret Secret, ok bool, err error)
}

// StorageFunc implements the Storage interface.
// This allows for simple functions to be used as Storage layers.
type StorageFunc func(string) (Secret, bool, error)

// FetchSecret takes and id string and returns the associated secret,
// If the secret is not present the returned boolean WILL BE FALSE.
// If something else went wrong during the fetch process err WILL NOT BE NIL.
func (s StorageFunc) FetchSecret(id string) (Secret, bool, error) {
	return s(id)
}
