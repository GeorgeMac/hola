package authentication

import "time"

type Option func(*Authenticator)

func WithExpirationLeeway(dur time.Duration) Option {
	return func(a *Authenticator) {
		a.validator.EXP = dur
	}
}

func WithNotBeforeLeeway(dur time.Duration) Option {
	return func(a *Authenticator) {
		a.validator.NBF = dur
	}
}

func WithSubject(sub string) Option {
	return func(a *Authenticator) {
		a.validator.SetSubject(sub)
	}
}

func WithAudience(aud string) Option {
	return func(a *Authenticator) {
		a.validator.SetAudience(aud)
	}
}
