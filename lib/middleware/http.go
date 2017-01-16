package middleware

import (
	"context"
	"fmt"
	"net/http"
	"sort"

	"github.com/georgemac/harry/lib/authentication"
	"github.com/pkg/errors"

	"gopkg.in/jose.v1/crypto"
	"gopkg.in/jose.v1/jws"
)

type HTTP struct {
	http.Handler
	auth *authentication.Authenticator
}

func New(handler http.Handler, auth *authentication.Authenticator) *HTTP {
	return &HTTP{Handler: handler, auth: auth}
}

func (h *HTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// parse JWT token using JOSE standard from request
	token, err := jws.ParseJWTFromRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if scopes, err := h.auth.Validate(token); err != nil {
		code := http.StatusInternalServerError
		switch errors.Cause(err) {
		case authentication.ErrISSClaimMissing,
			authentication.ErrScopesInvalid:
			// badly formatted requests
			code = http.StatusBadRequest
		case authentication.ErrCannotFindIdentity,
			authentication.ErrScopesUnauthorized,
			crypto.ErrSignatureInvalid:
			// unuathorized requests
			code = http.StatusUnauthorized
		}

		http.Error(w, err.Error(), code)
		return
	} else if len(scopes) > 0 {
		r = r.WithContext(context.WithValue(r.Context(), authentication.ScopesKey, scopes))
	}

	// call embedded handler
	h.Handler.ServeHTTP(w, r)
}

// subtract keys b from a
func subtract(a []interface{}, b []string) (res []string, err error) {
	sort.Strings(b)
	for _, v := range a {
		value, ok := v.(string)
		if !ok {
			err = fmt.Errorf("unexpected scope type %v", v)
			return
		}

		if i := sort.SearchStrings(b, value); i >= len(b) {
			res = append(res, value)
		}
	}

	return
}
