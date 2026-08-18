package jwt

import (
	"errors"
	"testing"
	"time"
)

func TestFutureIssuedAtRejected(t *testing.T) {
	claims := &RegisteredClaims{
		IssuedAt: NewNumericDate(time.Now().Add(1 * time.Hour)),
	}
	validator := NewValidator(WithIssuedAt())
	err := validator.Validate(claims)
	if err == nil {
		t.Fatal("expected error for future iat, got nil")
	}
	if !errors.Is(err, ErrTokenUsedBeforeIssued) {
		t.Fatalf("expected error %v, got %v", ErrTokenUsedBeforeIssued, err)
	}
}

func TestPastIssuedAtAccepted(t *testing.T) {
	claims := &RegisteredClaims{
		IssuedAt: NewNumericDate(time.Now().Add(-1 * time.Hour)),
	}
	validator := NewValidator(WithIssuedAt())
	err := validator.Validate(claims)
	if err != nil {
		t.Fatalf("expected no error for past iat, got %v", err)
	}
}

func TestIssuedAtWithLeeway(t *testing.T) {
	claims := &RegisteredClaims{
		IssuedAt: NewNumericDate(time.Now().Add(2 * time.Minute)),
	}
	// 0 leeway
	validator0 := NewValidator(WithIssuedAt())
	err0 := validator0.Validate(claims)
	if err0 == nil {
		t.Fatal("expected error for future iat with 0 leeway, got nil")
	}
	if !errors.Is(err0, ErrTokenUsedBeforeIssued) {
		t.Fatalf("expected error %v, got %v", ErrTokenUsedBeforeIssued, err0)
	}

	// 5 minutes leeway
	validator5 := NewValidator(WithIssuedAt(), WithLeeway(5*time.Minute))
	err5 := validator5.Validate(claims)
	if err5 != nil {
		t.Fatalf("expected no error for future iat with 5m leeway, got %v", err5)
	}
}
