package middleware

import (
	"context"
	"fmt"
	"net/http"
	"sort"

	"github.com/georgemac/harry/lib/identity"

	"gopkg.in/jose.v1/jws"
)

type ContextKey string

var (
	ScopesKey ContextKey = "scopes"
)

type HTTP struct {
	http.Handler
	storage identity.Storage
}

func New(handler http.Handler, storage identity.Storage) *HTTP {
	return &HTTP{Handler: handler, storage: storage}
}

func (h *HTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// parse JWT token using JOSE standard from request
	token, err := jws.ParseJWTFromRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// fetch the JWTs issuer claim
	iss, ok := token.Claims().Issuer()
	if !ok {
		http.Error(w, "ISS claim is missing", http.StatusBadRequest)
		return
	}

	// fetch identity for issuer
	id, ok, err := h.storage.FetchIdentity(iss)
	// something went wrong while fetching issuers identity
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// cannot locate identity in storage for issuer
	if !ok {
		http.Error(w, "ISS claim is invalid", http.StatusUnauthorized)
		return
	}

	// validate JWT token
	if err := id.Validate(token); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// if scopes present in claims, add scopes to request context
	if scopes := token.Claims().Get(string(ScopesKey)); scopes != nil {
		// only add scopes if they are present within identity
		if scopesSlice, ok := scopes.([]interface{}); !ok {
			message := fmt.Sprintf("scopes in unexpected format %v", scopes)
			http.Error(w, message, http.StatusBadRequest)
			return
		} else {
			unauthScopes, err := subtract(scopesSlice, id.Scopes)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			if len(unauthScopes) > 0 {
				message := fmt.Sprintf("scopes not supported %v", unauthScopes)
				http.Error(w, message, http.StatusUnauthorized)
				return
			}

			r = r.WithContext(context.WithValue(r.Context(), ScopesKey, scopesSlice))
		}
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
