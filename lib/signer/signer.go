package signer

import (
	"time"

	"gopkg.in/jose.v1/crypto"
	"gopkg.in/jose.v1/jws"
	"gopkg.in/jose.v1/jwt"

	uuid "github.com/satori/go.uuid"
)

var (
	now         = time.Now
	jti         = func() string { return uuid.NewV4().String() }
	fiveMinutes = 5 * time.Minute
)

type optionalString struct {
	valid bool
	value string
}

type Signer struct {
	dataKey  string
	sub, iss optionalString
	exp      time.Duration
	method   crypto.SigningMethod
}

func New(method crypto.SigningMethod, opts ...Option) *Signer {
	signer := &Signer{
		dataKey: "data",
		exp:     fiveMinutes,
		method:  method,
	}

	for _, opt := range opts {
		opt(signer)
	}

	return signer
}

func (s *Signer) Sign(data map[string]interface{}) jwt.JWT {
	now := now()
	claims := jws.Claims{}
	// set issued at to result of now()
	claims.SetIssuedAt(now)
	// set expiration to s.exp from now
	claims.SetExpiration(now.Add(s.exp))
	// set jti to new token from sequence
	claims.SetJWTID(jti())

	// set subject to codeship
	if s.sub.valid {
		claims.SetSubject(s.sub.value)
	}

	// set issuer to s.iss
	if s.iss.valid {
		claims.SetIssuer(s.iss.value)
	}

	// set custom data issued by caller
	claims.Set(s.dataKey, data)

	return jws.NewJWT(claims, s.method)
}
