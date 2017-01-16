package auth

import (
	"context"

	"github.com/pkg/errors"
)

var (
	// ErrContextUnexpectedScopesType is returned when the scopes embedded within a context
	// is not the expected slice of strings type
	ErrContextUnexpectedScopesType = errors.New("invalid type for scopes within context")
)

// ContextKey is a string used as a key in context and jwt transit
type ContextKey string

// String returns the underlying string type of the ContextKey
func (c ContextKey) String() string { return string(c) }

const (
	// ScopesKey is the string scopes, used with a context and a jwt.JWT claim
	ScopesKey ContextKey = "scopes"
)

// ScopesFromContext retrieves the string slices for the ScopesKey within a context.Context
// If the value for the key ScopesKey is not a slice of strings, an error ErrContextUnexpectedScopesType is returned
// If the scopes are not present, then the ok boolean is false
func ScopesFromContext(ctxt context.Context) (scopes []string, ok bool, err error) {
	if scopesPayload := ctxt.Value(ScopesKey); scopesPayload != nil {
		if scopes, ok = scopesPayload.([]string); ok {
			return
		}

		err = errors.Wrapf(ErrContextUnexpectedScopesType, `unexpected type "%v"`, scopesPayload)
		return
	}

	return
}

// WithScopes constructs a new context with the value scopes under the ScopesKey
func WithScopes(ctxt context.Context, scopes []string) context.Context {
	return context.WithValue(ctxt, ScopesKey, scopes)
}
