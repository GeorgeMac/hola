package identity

import (
	"gopkg.in/jose.v1/crypto"
	"gopkg.in/jose.v1/jwt"
)

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
