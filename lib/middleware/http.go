package middleware

import (
	"net/http"

	"github.com/georgemac/hola/lib/auth"
	"github.com/pkg/errors"

	"gopkg.in/jose.v1/crypto"
	"gopkg.in/jose.v1/jws"
)

// HTTP is an implementation of net/http.Handler
// It wraps another http Handler and performs token validation using
// an embedded auth.Authenticator. If the token is invalid, a suitable
// response is rendered via the http.ResponseWriter. Otherwise, the embedded
// handler is called and scopes are passed down via the request context.
type HTTP struct {
	http.Handler
	auth *auth.Authenticator
}

// New returns a pointer to a HTTP middleware, wrapping the provided Handler,
// using the provided Authenticator.
func New(handler http.Handler, auth *auth.Authenticator) *HTTP {
	return &HTTP{Handler: handler, auth: auth}
}

// ServeHTTP performs token validation and delegates result via the ResponseWriter
// or the embedded Handler if all verifies correctly.
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
		case auth.ErrISSClaimMissing,
			auth.ErrScopesInvalid:
			// badly formatted requests
			code = http.StatusBadRequest
		case auth.ErrCannotFindIdentity,
			auth.ErrScopesUnauthorized,
			crypto.ErrSignatureInvalid:
			// unuathorized requests
			code = http.StatusUnauthorized
		}

		http.Error(w, err.Error(), code)
		return
	} else if len(scopes) > 0 {
		// scopes added to requests context
		r = r.WithContext(auth.WithScopes(r.Context(), scopes))
	}

	// call embedded handler
	h.Handler.ServeHTTP(w, r)
}
