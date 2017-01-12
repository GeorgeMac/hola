package authentication

import (
	"time"

	"github.com/pkg/errors"
	"gopkg.in/jose.v1/jws"
	"gopkg.in/jose.v1/jwt"
)

var (
	// ErrSecretNotFound is returned when a secret key cannot be located in the underlying
	// storage for a given key ID.
	ErrSecretNotFound = errors.Errorf("authentication: secret not found")

	// ErrIDKeyMissing is returned when the secret ID key is missing from the JWT token claims.
	ErrIDKeyMissing = errors.Errorf("authentication: secret ID key missing from token claims")

	// ErrIDUnexpectedType is returned when the secret ID key is present but not encoded as a string.
	ErrIDUnexpectedType = errors.Errorf("authentication: secret ID is present but is not a string")
)

type Authenticator struct {
	idKey     string
	storage   Storage
	validator *jwt.Validator
}

// New create a new(Authenticator) around a Storage implementation
// and a variadic set of Options.
func New(storage Storage, opts ...Option) *Authenticator {
	a := &Authenticator{
		idKey:     "id_key",
		validator: jws.NewValidator(jws.Claims{}, time.Second, time.Second, nil),
	}

	for _, opt := range opts {
		opt(a)
	}

	return a
}

// Validate looks up a secrets with the underlying Storage implementation
// using the secret ID found within the claims of the JWT token.
func (a *Authenticator) Validate(token jwt.JWT) error {
	var (
		id string
		ok bool
	)

	// fetch id for secret from token claims
	// e.g. { "key_id": "some-id-for-secret" }["key_id"]
	if idValue := token.Claims().Get(a.idKey); idValue == nil {
		return errors.Wrapf(ErrIDKeyMissing, "for given secret ID key (%s)", a.idKey)
	} else if id, ok = idValue.(string); !ok {
		return errors.Wrapf(ErrIDUnexpectedType, "secret ID value (%v) type (%T)", idValue, idValue)
	}

	// attempt to fetch secret for ID from underlying storage
	secret, present, err := a.storage.FetchSecret(id)
	if err != nil {
		return errors.Wrapf(err, "authentication: error fetching secret for ID (%s)", id)
	}

	// if the secret is not present, return an error
	if !present {
		return errors.Wrapf(ErrSecretNotFound, "for given ID (%s)", id)
	}

	// validate the claims
	if err := secret.Validate(token); err != nil {
		return errors.Wrap(err, "authentication: error validating token")
	}

	return nil
}
