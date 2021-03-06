package middleware

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gopkg.in/jose.v1/crypto"
	"gopkg.in/jose.v1/jws"

	"github.com/georgemac/hola/lib/auth"
	"github.com/georgemac/hola/lib/identity"
	"github.com/georgemac/legs"
	"github.com/stretchr/testify/assert"
)

var (
	method = crypto.SigningMethodHS256
	secret = "this is super secret"
)

func TestHTTP(t *testing.T) {
	legs.Table{
		httpTestCase{
			name:    "missing JWT token",
			request: request(),
			code:    http.StatusBadRequest,
			body:    "no token present in request\n",
		},
		httpTestCase{
			name: "missing JWT iss claim",
			// request with JWT, but no issuer claim
			request: tokenRequest("test.audience.com", ""),
			code:    http.StatusBadRequest,
			body:    "authentication: ISS missing from JWT claims\n",
		},
		httpTestCase{
			name:    "error when fetching identity from storage",
			request: tokenRequest("test.audience.com", "some-issuer-key"),
			code:    http.StatusInternalServerError,
			storage: identity.FetcherFunc(func(iss string) (identity.Identity, bool, error) {
				assert.Equal(t, "some-issuer-key", iss)
				return identity.Identity{}, false, errors.New("something went wrong in storage")
			}),
			body: "authentication: error fetching identity from storage: something went wrong in storage\n",
		},
		httpTestCase{
			name:    "No identity for ISS claim",
			request: tokenRequest("test.audience.com", "some-issuer-key"),
			code:    http.StatusUnauthorized,
			storage: identity.FetcherFunc(func(iss string) (identity.Identity, bool, error) {
				assert.Equal(t, "some-issuer-key", iss)
				return identity.Identity{}, false, nil
			}),
			body: "authentication: identity cannot be located for ISS claim\n",
		},
		httpTestCase{
			name:    "signature is invalid",
			request: tokenRequest("test.audience.com", "some-issuer-key"),
			code:    http.StatusUnauthorized,
			storage: identity.FetcherFunc(func(iss string) (identity.Identity, bool, error) {
				assert.Equal(t, "some-issuer-key", iss)
				return identity.Identity{
					Secret: []byte("some invalid secret"),
					Method: crypto.SigningMethodHS256,
				}, true, nil
			}),
			body: "authentication: token is invalid: signature is invalid\n",
		},
		httpTestCase{
			name:    "valid signature with no scopes",
			request: tokenRequest("test.audience.com", "some-issuer-key"),
			code:    http.StatusOK,
			storage: identity.FetcherFunc(func(iss string) (identity.Identity, bool, error) {
				assert.Equal(t, "some-issuer-key", iss)
				return identity.Identity{
					Secret: []byte("this is super secret"),
					Method: crypto.SigningMethodHS256,
				}, true, nil
			}),
			body: "called\n",
		},
		httpTestCase{
			name:    "valid signature with scopes in unexpected format",
			request: invalidScopeTokenRequest("test.audience.com", "some-issuer-key"),
			code:    http.StatusBadRequest,
			storage: identity.FetcherFunc(func(iss string) (identity.Identity, bool, error) {
				assert.Equal(t, "some-issuer-key", iss)
				return identity.Identity{
					Secret: []byte("this is super secret"),
					Method: crypto.SigningMethodHS256,
				}, true, nil
			}),
			body: "authentication: found 12345: invalid scopes in JWT claims\n",
		},
		httpTestCase{
			name:    "valid signature with unauthorized scopes",
			request: tokenRequest("test.audience.com", "some-issuer-key", "resource.action"),
			code:    http.StatusUnauthorized,
			storage: identity.FetcherFunc(func(iss string) (identity.Identity, bool, error) {
				assert.Equal(t, "some-issuer-key", iss)
				return identity.Identity{
					Secret: []byte("this is super secret"),
					Method: crypto.SigningMethodHS256,
				}, true, nil
			}),
			body: "authentication: found [resource.action]: scopes not authorized for ISS\n",
		},
		httpTestCase{
			name:    "valid signature with unexpected scope types",
			request: tokenRequest("test.audience.com", "some-issuer-key", 5),
			code:    http.StatusBadRequest,
			storage: identity.FetcherFunc(func(iss string) (identity.Identity, bool, error) {
				assert.Equal(t, "some-issuer-key", iss)
				return identity.Identity{
					Secret: []byte("this is super secret"),
					Method: crypto.SigningMethodHS256,
					Scopes: []string{"resource.action", "other.action"},
				}, true, nil
			}),
			body: "authentication: unexpected scope type 5: invalid scopes in JWT claims\n",
		},
		httpTestCase{
			name:    "valid signature with authorized scopes",
			request: tokenRequest("test.audience.com", "some-issuer-key", "resource.action"),
			code:    http.StatusOK,
			storage: identity.FetcherFunc(func(iss string) (identity.Identity, bool, error) {
				assert.Equal(t, "some-issuer-key", iss)
				return identity.Identity{
					Secret: []byte("this is super secret"),
					Method: crypto.SigningMethodHS256,
					Scopes: []string{"resource.action", "other.action"},
				}, true, nil
			}),
			body:   "called\n",
			scopes: []string{"resource.action"},
		},
	}.Run(t)
}

type httpTestCase struct {
	// name
	name string
	// inputs
	request *http.Request
	// outputs
	code   int
	body   string
	scopes []string
	// state
	storage identity.Fetcher
}

func (h httpTestCase) Name() string { return h.name }

func (h httpTestCase) Run(t *testing.T) {
	assert := assert.New(t)

	// record http response from handler
	recorder := httptest.NewRecorder()

	// wrapped is a http.Handler that records the context
	wrapped := &contextRecorder{}

	// construct a new handler to test
	handler := New(wrapped, auth.New(h.storage))

	// run request handler
	handler.ServeHTTP(recorder, h.request)

	// assert that the status was as expected
	assert.Equal(h.code, recorder.Code)

	// assert that the body contents is as expected
	assert.Equal(h.body, recorder.Body.String())

	if h.scopes != nil {
		// check scopes as expected
		assert.Equal(h.scopes, wrapped.ctxt.Value(auth.ScopesKey))
	}
}

// useful mocks and types

func invalidScopeTokenRequest(aud, iss string) *http.Request {
	token := jws.NewJWT(jws.Claims{
		"aud": aud,
		"iss": iss,
		string(auth.ScopesKey): 12345,
	}, method)

	serialToken, err := token.Serialize([]byte(secret))
	if err != nil {
		panic(err)
	}

	var bearer bytes.Buffer
	fmt.Fprintf(&bearer, "BEARER %s", string(serialToken))

	request := request()
	request.Header.Set("Authorization", bearer.String())

	return request
}

func tokenRequest(aud, iss string, scopes ...interface{}) *http.Request {
	claims := jws.Claims{}
	claims.SetAudience(aud)
	if iss != "" {
		claims.SetIssuer(iss)
	}

	if len(scopes) > 0 {
		claims.Set(string(auth.ScopesKey), scopes)
	}

	request := request()
	token := jws.NewJWT(claims, method)

	serialToken, err := token.Serialize([]byte(secret))
	if err != nil {
		panic(err)
	}

	var bearer bytes.Buffer
	fmt.Fprintf(&bearer, "BEARER %s", string(serialToken))
	request.Header.Set("Authorization", bearer.String())

	return request
}

func request() *http.Request {
	return httptest.NewRequest("GET", "/some/auth", strings.NewReader("some body"))
}

type contextRecorder struct {
	ctxt context.Context
}

func (h *contextRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.ctxt = r.Context()
	w.Write([]byte("called\n"))
}
