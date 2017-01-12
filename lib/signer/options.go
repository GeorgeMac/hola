package signer

import "time"

type Option func(*Signer)

func WithDataKey(key string) Option {
	return func(s *Signer) {
		s.dataKey = key
	}
}

func WithExpiration(exp time.Duration) Option {
	return func(s *Signer) {
		s.exp = exp
	}
}

func WithSubject(sub string) Option {
	return func(s *Signer) {
		s.sub = optionalString{valid: true, value: sub}
	}
}

func WithIssuer(iss string) Option {
	return func(s *Signer) {
		s.iss = optionalString{valid: true, value: iss}
	}
}
