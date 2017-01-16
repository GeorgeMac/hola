package identity

import (
	"gopkg.in/jose.v1/crypto"
	"gopkg.in/jose.v1/jws"
	"gopkg.in/jose.v1/jwt"
)

// Identity is a struct which contains a secret used
// to decode a token and the relevant signing mechanism
// used to encode it in the first place.
type Identity struct {
	Key    string               `yaml:"key"`
	Secret []byte               `yaml:"secret"`
	Scopes []string             `yaml:"scopes"`
	Method crypto.SigningMethod `yaml:"signing_method"`
}

// Validate calls validate on the JWT token with
// the data and method embedded within the struct.
func (i Identity) Validate(token jwt.JWT) error {
	return token.Validate(i.Secret, i.Method)
}

type identity struct {
	Key    string   `yaml:"key"`
	Secret string   `yaml:"secret"`
	Scopes []string `yaml:"scopes"`
	Method string   `yaml:"signing_method"`
}

// UnmarshalYAML performs custom yaml unmarshalling to parse Identities properly
func (i *Identity) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var identity identity
	if err := unmarshal(&identity); err != nil {
		return err
	}

	i.Key = identity.Key
	i.Secret = []byte(identity.Secret)
	i.Scopes = identity.Scopes
	i.Method = jws.GetSigningMethod(identity.Method)

	return nil
}
