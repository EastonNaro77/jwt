package jwt

import "errors"

// Error constants
var (
	ErrTokenMalformed        = errors.New("token is malformed")
	ErrTokenUnverifiable     = errors.New("token is unverifiable")
	ErrTokenSignatureInvalid = errors.New("token signature is invalid")

	// The following errors are returned by the MapClaims Validator
	ErrTokenExpired              = errors.New("token is expired")
	ErrTokenNotYetValid          = errors.New("token is not yet valid")
	ErrTokenInvalidAudience      = errors.New("token has invalid audience")
	ErrTokenInvalidIssuer        = errors.New("token has invalid issuer")
	ErrTokenInvalidSubject       = errors.New("token has invalid subject")
	ErrTokenInvalidId            = errors.New("token has invalid id")
	ErrTokenClaimsInvalid        = errors.New("token has invalid claims")
	ErrTokenRequiredClaimMissing = errors.New("token is missing required claim")
	ErrTokenUsedBeforeIssued     = errors.New("token used before issued")
)
