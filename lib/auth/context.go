package auth

import (
	"context"

	"github.com/pkg/errors"
)

var (
	ErrContextUnexpectedScopesType = errors.New("invalid type for scopes within context")
)

type ContextKey string

func (c ContextKey) String() string { return string(c) }

const (
	ScopesKey ContextKey = "scopes"
)

func ScopesFromContext(ctxt context.Context) (scopes []string, ok bool, err error) {
	if scopesPayload := ctxt.Value(ScopesKey.String()); scopesPayload != nil {
		if scopes, ok = scopesPayload.([]string); ok {
			return
		}

		err = errors.Wrapf(ErrContextUnexpectedScopesType, `unexpected type "%v"`, scopesPayload)
		return
	}

	return
}
