package auth

import "time"

// Option is a function which manipulates the state of an Authenticator
type Option func(*Authenticator)

// WithExpirationLeeway sets the JWT validators expiration duration
func WithExpirationLeeway(dur time.Duration) Option {
	return func(a *Authenticator) {
		a.validator.EXP = dur
	}
}

// WithNotBeforeLeeway sets the JWT validators not before leeway duration
func WithNotBeforeLeeway(dur time.Duration) Option {
	return func(a *Authenticator) {
		a.validator.NBF = dur
	}
}

// WithSubject enforces the subject within the JWT claims at validation
func WithSubject(sub string) Option {
	return func(a *Authenticator) {
		a.validator.SetSubject(sub)
	}
}

// WithAudience enforces the audience within the JWT claims at validation
func WithAudience(aud string) Option {
	return func(a *Authenticator) {
		a.validator.SetAudience(aud)
	}
}
