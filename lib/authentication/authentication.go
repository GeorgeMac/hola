package authentication

import (
	"sort"
	"time"

	"github.com/georgemac/harry/lib/identity"
	"github.com/pkg/errors"
	"gopkg.in/jose.v1/jws"
	"gopkg.in/jose.v1/jwt"
)

type ContextKey string

const (
	ScopesKey ContextKey = "scopes"
)

var (
	// ErrSecretNotFound is returned when a secret key cannot be located in the underlying
	// storage for a given key ID.
	ErrSecretNotFound = errors.New("secret not found")

	// ErrISSClaimMissing is returned when the secret ID key is missing from the JWT token claims.
	ErrISSClaimMissing = errors.New("ISS missing from JWT claims")

	// ErrCannotFindIdentity is returned when an identity cannot be located for an ISS key.
	ErrCannotFindIdentity = errors.New("identity cannot be located for ISS claim")

	// ErrScopesInvalid is returned when an error occurs parsing scopes from JWT claims
	ErrScopesInvalid = errors.New("invalid scopes in JWT claims")

	// ErrScopesUnauthorized is returned when the scopes present aren't valid for ISS key.
	ErrScopesUnauthorized = errors.New("scopes not authorized for ISS")
)

type Authenticator struct {
	storage   identity.Storage
	validator *jwt.Validator
}

// New create a new(Authenticator) around a Storage implementation
// and a variadic set of Options.
func New(storage identity.Storage, opts ...Option) *Authenticator {
	a := &Authenticator{
		storage:   storage,
		validator: jws.NewValidator(jws.Claims{}, time.Second, time.Second, nil),
	}

	for _, opt := range opts {
		opt(a)
	}

	return a
}

// Validate looks up a secrets with the underlying Storage implementation
// using the secret ID found within the claims of the JWT token.
func (a *Authenticator) Validate(token jwt.JWT) (scopes []string, err error) {
	// fetch the JWTs issuer claim
	iss, ok := token.Claims().Issuer()
	if !ok {
		return scopes, errors.Wrap(ErrISSClaimMissing, "authentication")
	}

	// fetch identity for issuer
	id, ok, err := a.storage.FetchIdentity(iss)
	// something went wrong while fetching issuers identity
	if err != nil {
		return scopes, errors.Wrap(err, "authentication: error fetching identity from storage")
	}

	// cannot locate identity in storage for issuer
	if !ok {
		return scopes, errors.Wrap(ErrCannotFindIdentity, "authentication")
	}

	// validate JWT token
	if err := id.Validate(token); err != nil {
		return scopes, errors.Wrap(err, "authentication: token is invalid")
	}

	// if scopes present in claims, add scopes to request context
	if scopesPlayload := token.Claims().Get(string(ScopesKey)); scopesPlayload != nil {
		// only add scopes if they are present within identity
		scopesSlice, ok := scopesPlayload.([]interface{})
		if !ok {
			return scopes, errors.Wrapf(ErrScopesInvalid, "authentication: found %v", scopesPlayload)
		}

		var invalid []string
		scopes, invalid, err = checkScopes(scopesSlice, id.Scopes)
		if err != nil {
			return scopes, errors.Wrapf(ErrScopesInvalid, "authentication: %s", err.Error())
		}

		if len(invalid) > 0 {
			err = errors.Wrapf(ErrScopesUnauthorized, "authentication: found %v", invalid)
		}
	}

	return
}

// checkScopes returns two slices, valid and invalid
// valid contains scopes in a, that are present in b
// invalid contains the scopes in a, that are not present in b
// err is not nil, if a scope in a is not a string
func checkScopes(a []interface{}, b []string) (valid, invalid []string, err error) {
	sort.Strings(b)
	for _, v := range a {
		value, ok := v.(string)
		if !ok {
			err = errors.Errorf("unexpected scope type %v", v)
			return
		}

		if i := sort.SearchStrings(b, value); i >= len(b) {
			invalid = append(invalid, value)
		} else {
			valid = append(valid, value)
		}
	}

	return
}
