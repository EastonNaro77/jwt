package jwt

import (
	"errors"
	"fmt"
	"time"
)

// Option is a configuration option for the Validator.
type Option func(*Validator)

// Validator is a helper for validating claims.
type Validator struct {
	leeway        time.Duration
	expectedAud   string
	expectedIss   string
	expectedSub   string
	expectedValid bool
	verifyIat     bool
}

// NewValidator creates a new Validator.
func NewValidator(opts ...Option) *Validator {
	v := &Validator{
		expectedValid: true,
	}

	for _, opt := range opts {
		opt(v)
	}

	return v
}

// WithLeeway specifies the leeway for time-based claims.
func WithLeeway(d time.Duration) Option {
	return func(v *Validator) {
		v.leeway = d
	}
}

// WithAudience specifies the expected audience.
func WithAudience(aud string) Option {
	return func(v *Validator) {
		v.expectedAud = aud
	}
}

// WithIssuer specifies the expected issuer.
func WithIssuer(iss string) Option {
	return func(v *Validator) {
		v.expectedIss = iss
	}
}

// WithSubject specifies the expected subject.
func WithSubject(sub string) Option {
	return func(v *Validator) {
		v.expectedSub = sub
	}
}

// WithoutClaimsValidation disables the default validation of exp and nbf.
func WithoutClaimsValidation() Option {
	return func(v *Validator) {
		v.expectedValid = false
	}
}

// WithIssuedAt enables verification of the iat claim.
func WithIssuedAt() Option {
	return func(v *Validator) {
		v.verifyIat = true
	}
}

// Validate validates the claims.
func (v *Validator) Validate(claims Claims) error {
	var errs []error
	now := time.Now()

	if v.expectedValid {
		if exp, err := claims.GetExpirationTime(); err != nil {
			errs = append(errs, err)
		} else if exp != nil {
			if now.Add(-v.leeway).After(exp.Time) {
				errs = append(errs, fmt.Errorf("%w: %s", ErrTokenExpired, exp.Time))
			}
		}

		if nbf, err := claims.GetNotBefore(); err != nil {
			errs = append(errs, err)
		} else if nbf != nil {
			if now.Add(v.leeway).Before(nbf.Time) {
				errs = append(errs, fmt.Errorf("%w: %s", ErrTokenNotYetValid, nbf.Time))
			}
		}
	}

	if v.expectedAud != "" {
		if aud, err := claims.GetAudience(); err != nil {
			errs = append(errs, err)
		} else if aud != nil {
			var found bool
			for _, a := range aud {
				if a == v.expectedAud {
					found = true
					break
				}
			}
			if !found {
				errs = append(errs, fmt.Errorf("%w: expected %s", ErrTokenInvalidAudience, v.expectedAud))
			}
		} else {
			errs = append(errs, fmt.Errorf("%w: expected %s", ErrTokenInvalidAudience, v.expectedAud))
		}
	}

	if v.expectedIss != "" {
		if iss, err := claims.GetIssuer(); err != nil {
			errs = append(errs, err)
		} else if iss != v.expectedIss {
			errs = append(errs, fmt.Errorf("%w: expected %s, got %s", ErrTokenInvalidIssuer, v.expectedIss, iss))
		}
	}

	if v.expectedSub != "" {
		if sub, err := claims.GetSubject(); err != nil {
			errs = append(errs, err)
		} else if sub != v.expectedSub {
			errs = append(errs, fmt.Errorf("%w: expected %s, got %s", ErrTokenInvalidSubject, v.expectedSub, sub))
		}
	}

	if v.verifyIat {
		if iat, err := claims.GetIssuedAt(); err != nil {
			errs = append(errs, err)
		} else if iat == nil {
			errs = append(errs, fmt.Errorf("%w: iat claim is required", ErrTokenRequiredClaimMissing))
		} else {
			if now.Add(v.leeway).Before(iat.Time) {
				errs = append(errs, fmt.Errorf("%w: %s", ErrTokenUsedBeforeIssued, iat.Time))
			}
		}
	}

	return errors.Join(errs...)
}
