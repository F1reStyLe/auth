package auth

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type repositoryMock struct {
	createUserFn            func(context.Context, CreateUserParams) (*User, error)
	getUserByIDFn           func(context.Context, int64) (*User, error)
	getUserByUsernameFn     func(context.Context, string) (*User, error)
	getUserByEmailFn        func(context.Context, string) (*User, error)
	createSessionFn         func(context.Context, CreateSessionParams) (*Session, error)
	getSessionByTokenHashFn func(context.Context, string) (*Session, error)
	rotateSessionTokenFn    func(context.Context, int64, string, time.Time, time.Time) (*Session, error)
	revokeSessionByHashFn   func(context.Context, string, time.Time) error
	revokeAllSessionsFn     func(context.Context, int64, time.Time) error
	createOneTimeTokenFn    func(context.Context, CreateOneTimeTokenParams) (*OneTimeToken, error)
	getValidTokenFn         func(context.Context, string, string) (*OneTimeToken, error)
	consumeOneTimeTokenFn   func(context.Context, int64, time.Time) error
	replaceOneTimeTokenFn   func(context.Context, CreateOneTimeTokenParams) (*OneTimeToken, error)
	markEmailVerifiedFn     func(context.Context, int64, time.Time) error
	updatePasswordHashFn    func(context.Context, int64, string) error
}

func (m *repositoryMock) CreateUser(ctx context.Context, params CreateUserParams) (*User, error) {
	return m.createUserFn(ctx, params)
}

func (m *repositoryMock) GetUserByID(ctx context.Context, id int64) (*User, error) {
	return m.getUserByIDFn(ctx, id)
}

func (m *repositoryMock) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	return m.getUserByUsernameFn(ctx, username)
}

func (m *repositoryMock) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	return m.getUserByEmailFn(ctx, email)
}

func (m *repositoryMock) CreateSession(ctx context.Context, params CreateSessionParams) (*Session, error) {
	return m.createSessionFn(ctx, params)
}

func (m *repositoryMock) GetSessionByTokenHash(ctx context.Context, tokenHash string) (*Session, error) {
	return m.getSessionByTokenHashFn(ctx, tokenHash)
}

func (m *repositoryMock) RotateSessionToken(ctx context.Context, sessionID int64, tokenHash string, expiresAt time.Time, lastUsedAt time.Time) (*Session, error) {
	return m.rotateSessionTokenFn(ctx, sessionID, tokenHash, expiresAt, lastUsedAt)
}

func (m *repositoryMock) RevokeSessionByTokenHash(ctx context.Context, tokenHash string, revokedAt time.Time) error {
	return m.revokeSessionByHashFn(ctx, tokenHash, revokedAt)
}

func (m *repositoryMock) RevokeAllUserSessions(ctx context.Context, userID int64, revokedAt time.Time) error {
	return m.revokeAllSessionsFn(ctx, userID, revokedAt)
}

func (m *repositoryMock) CreateOneTimeToken(ctx context.Context, params CreateOneTimeTokenParams) (*OneTimeToken, error) {
	return m.createOneTimeTokenFn(ctx, params)
}

func (m *repositoryMock) GetValidOneTimeToken(ctx context.Context, purpose, tokenHash string) (*OneTimeToken, error) {
	return m.getValidTokenFn(ctx, purpose, tokenHash)
}

func (m *repositoryMock) ConsumeOneTimeToken(ctx context.Context, tokenID int64, consumedAt time.Time) error {
	return m.consumeOneTimeTokenFn(ctx, tokenID, consumedAt)
}

func (m *repositoryMock) ReplaceOneTimeToken(ctx context.Context, params CreateOneTimeTokenParams) (*OneTimeToken, error) {
	return m.replaceOneTimeTokenFn(ctx, params)
}

func (m *repositoryMock) MarkUserEmailVerified(ctx context.Context, userID int64, verifiedAt time.Time) error {
	return m.markEmailVerifiedFn(ctx, userID, verifiedAt)
}

func (m *repositoryMock) UpdatePasswordHash(ctx context.Context, userID int64, passwordHash string) error {
	return m.updatePasswordHashFn(ctx, userID, passwordHash)
}

type tokenManagerMock struct {
	generateFn func(time.Duration, int64) (string, error)
}

func (m tokenManagerMock) Generate(exp time.Duration, userID int64) (string, error) {
	return m.generateFn(exp, userID)
}

func TestServiceLoginRequiresVerifiedEmail(t *testing.T) {
	t.Parallel()

	passwordHash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword: %v", err)
	}

	svc := NewService(
		&repositoryMock{
			getUserByEmailFn: func(context.Context, string) (*User, error) {
				return &User{
					ID:           7,
					Email:        "user@example.com",
					PasswordHash: string(passwordHash),
				}, nil
			},
			getUserByUsernameFn: func(context.Context, string) (*User, error) { return nil, errors.New("unexpected call") },
		},
		tokenManagerMock{generateFn: func(time.Duration, int64) (string, error) { return "", errors.New("unexpected token generation") }},
		15*time.Minute,
		24*time.Hour,
		24*time.Hour,
		time.Hour,
	)

	_, err = svc.Login(context.Background(), LoginRequest{
		Email:    "user@example.com",
		Password: "secret",
	})
	if !errors.Is(err, ErrEmailNotVerified) {
		t.Fatalf("Login error = %v, want %v", err, ErrEmailNotVerified)
	}
}

func TestServiceRefreshRotatesSession(t *testing.T) {
	t.Parallel()

	oldToken := "old-refresh-token"
	oldHash := hashToken(oldToken)
	var rotatedHash string

	svc := NewService(
		&repositoryMock{
			getSessionByTokenHashFn: func(_ context.Context, tokenHash string) (*Session, error) {
				if tokenHash != oldHash {
					t.Fatalf("GetSessionByTokenHash hash = %q, want %q", tokenHash, oldHash)
				}
				return &Session{
					ID:        11,
					UserID:    42,
					TokenHash: oldHash,
					ExpiresAt: time.Now().UTC().Add(time.Hour),
				}, nil
			},
			rotateSessionTokenFn: func(_ context.Context, sessionID int64, tokenHash string, expiresAt time.Time, lastUsedAt time.Time) (*Session, error) {
				if sessionID != 11 {
					t.Fatalf("RotateSessionToken sessionID = %d, want 11", sessionID)
				}
				if tokenHash == oldHash || tokenHash == "" {
					t.Fatalf("RotateSessionToken tokenHash = %q, want new non-empty hash", tokenHash)
				}
				if expiresAt.Before(lastUsedAt) {
					t.Fatal("RotateSessionToken expiresAt should be after lastUsedAt")
				}
				rotatedHash = tokenHash
				return &Session{
					ID:         sessionID,
					UserID:     42,
					TokenHash:  tokenHash,
					ExpiresAt:  expiresAt,
					LastUsedAt: &lastUsedAt,
				}, nil
			},
		},
		tokenManagerMock{generateFn: func(exp time.Duration, userID int64) (string, error) {
			if exp != 15*time.Minute || userID != 42 {
				t.Fatalf("Generate called with exp=%v userID=%d", exp, userID)
			}
			return "access-token", nil
		}},
		15*time.Minute,
		24*time.Hour,
		24*time.Hour,
		time.Hour,
	)

	resp, err := svc.Refresh(context.Background(), RefreshTokenRequest{RefreshToken: oldToken})
	if err != nil {
		t.Fatalf("Refresh returned error: %v", err)
	}
	if resp.AccessToken != "access-token" {
		t.Fatalf("AccessToken = %q, want %q", resp.AccessToken, "access-token")
	}
	if resp.RefreshToken == "" || resp.RefreshToken == oldToken {
		t.Fatalf("RefreshToken = %q, want new non-empty token", resp.RefreshToken)
	}
	if hashToken(resp.RefreshToken) != rotatedHash {
		t.Fatalf("rotated refresh token hash mismatch")
	}
}

func TestServiceVerifyEmailConsumesTokenAndMarksUser(t *testing.T) {
	t.Parallel()

	rawToken := "verify-token"
	expectedHash := hashToken(rawToken)
	consumed := false
	marked := false

	svc := NewService(
		&repositoryMock{
			getValidTokenFn: func(_ context.Context, purpose, tokenHash string) (*OneTimeToken, error) {
				if purpose != tokenPurposeVerifyEmail {
					t.Fatalf("purpose = %q, want %q", purpose, tokenPurposeVerifyEmail)
				}
				if tokenHash != expectedHash {
					t.Fatalf("tokenHash = %q, want %q", tokenHash, expectedHash)
				}
				return &OneTimeToken{
					ID:        5,
					UserID:    99,
					Purpose:   purpose,
					TokenHash: tokenHash,
					ExpiresAt: time.Now().UTC().Add(time.Hour),
				}, nil
			},
			consumeOneTimeTokenFn: func(_ context.Context, tokenID int64, _ time.Time) error {
				if tokenID != 5 {
					t.Fatalf("tokenID = %d, want 5", tokenID)
				}
				consumed = true
				return nil
			},
			markEmailVerifiedFn: func(_ context.Context, userID int64, _ time.Time) error {
				if userID != 99 {
					t.Fatalf("userID = %d, want 99", userID)
				}
				marked = true
				return nil
			},
		},
		tokenManagerMock{generateFn: func(time.Duration, int64) (string, error) { return "", nil }},
		15*time.Minute,
		24*time.Hour,
		24*time.Hour,
		time.Hour,
	)

	if err := svc.VerifyEmail(context.Background(), VerifyEmailRequest{Token: rawToken}); err != nil {
		t.Fatalf("VerifyEmail returned error: %v", err)
	}
	if !consumed {
		t.Fatal("expected token to be consumed")
	}
	if !marked {
		t.Fatal("expected user to be marked verified")
	}
}

func TestServiceResetPasswordUpdatesHashAndRevokesSessions(t *testing.T) {
	t.Parallel()

	rawToken := "reset-token"
	expectedHash := hashToken(rawToken)
	var updatedHash string
	revoked := false

	svc := NewService(
		&repositoryMock{
			getValidTokenFn: func(_ context.Context, purpose, tokenHash string) (*OneTimeToken, error) {
				if purpose != tokenPurposeResetPassword {
					t.Fatalf("purpose = %q, want %q", purpose, tokenPurposeResetPassword)
				}
				if tokenHash != expectedHash {
					t.Fatalf("tokenHash = %q, want %q", tokenHash, expectedHash)
				}
				return &OneTimeToken{
					ID:        3,
					UserID:    77,
					Purpose:   purpose,
					TokenHash: tokenHash,
					ExpiresAt: time.Now().UTC().Add(time.Hour),
				}, nil
			},
			consumeOneTimeTokenFn: func(context.Context, int64, time.Time) error { return nil },
			updatePasswordHashFn: func(_ context.Context, userID int64, passwordHash string) error {
				if userID != 77 {
					t.Fatalf("userID = %d, want 77", userID)
				}
				updatedHash = passwordHash
				return nil
			},
			revokeAllSessionsFn: func(_ context.Context, userID int64, _ time.Time) error {
				if userID != 77 {
					t.Fatalf("userID = %d, want 77", userID)
				}
				revoked = true
				return nil
			},
		},
		tokenManagerMock{generateFn: func(time.Duration, int64) (string, error) { return "", nil }},
		15*time.Minute,
		24*time.Hour,
		24*time.Hour,
		time.Hour,
	)

	if err := svc.ResetPassword(context.Background(), ResetPasswordRequest{
		Token:       rawToken,
		NewPassword: "new-secret",
	}); err != nil {
		t.Fatalf("ResetPassword returned error: %v", err)
	}
	if updatedHash == "" {
		t.Fatal("expected password hash to be updated")
	}
	if bcrypt.CompareHashAndPassword([]byte(updatedHash), []byte("new-secret")) != nil {
		t.Fatal("stored hash does not match new password")
	}
	if !revoked {
		t.Fatal("expected all sessions to be revoked")
	}
}

func TestServiceLogoutRevokesSessionByHashedToken(t *testing.T) {
	t.Parallel()

	rawToken := "logout-token"
	expectedHash := hashToken(rawToken)

	svc := NewService(
		&repositoryMock{
			revokeSessionByHashFn: func(_ context.Context, tokenHash string, revokedAt time.Time) error {
				if tokenHash != expectedHash {
					t.Fatalf("tokenHash = %q, want %q", tokenHash, expectedHash)
				}
				if revokedAt.IsZero() {
					t.Fatal("expected non-zero revokedAt")
				}
				return nil
			},
		},
		tokenManagerMock{generateFn: func(time.Duration, int64) (string, error) { return "", nil }},
		15*time.Minute,
		24*time.Hour,
		24*time.Hour,
		time.Hour,
	)

	if err := svc.Logout(context.Background(), LogoutRequest{RefreshToken: rawToken}); err != nil {
		t.Fatalf("Logout returned error: %v", err)
	}
}

func TestServiceRequestPasswordResetUnknownEmailIsAccepted(t *testing.T) {
	t.Parallel()

	svc := NewService(
		&repositoryMock{
			getUserByEmailFn: func(context.Context, string) (*User, error) { return nil, ErrInvalidCredentials },
		},
		tokenManagerMock{generateFn: func(time.Duration, int64) (string, error) { return "", nil }},
		15*time.Minute,
		24*time.Hour,
		24*time.Hour,
		time.Hour,
	)

	resp, err := svc.RequestPasswordReset(context.Background(), RequestPasswordResetRequest{Email: "missing@example.com"})
	if err != nil {
		t.Fatalf("RequestPasswordReset returned error: %v", err)
	}
	if resp.Status != "accepted" {
		t.Fatalf("status = %q, want %q", resp.Status, "accepted")
	}
	if resp.Token != "" {
		t.Fatalf("token = %q, want empty", resp.Token)
	}
}

func TestGetUserPrefersEmailLookup(t *testing.T) {
	t.Parallel()

	svc := NewService(
		&repositoryMock{
			getUserByEmailFn: func(_ context.Context, email string) (*User, error) {
				if email != "user@example.com" {
					t.Fatalf("email = %q, want normalized email", email)
				}
				return &User{ID: 1}, nil
			},
			getUserByUsernameFn: func(context.Context, string) (*User, error) {
				return nil, fmt.Errorf("username lookup should not be called")
			},
		},
		tokenManagerMock{generateFn: func(time.Duration, int64) (string, error) { return "", nil }},
		15*time.Minute,
		24*time.Hour,
		24*time.Hour,
		time.Hour,
	)

	user, err := getUser(svc, context.Background(), LoginRequest{
		Email:    " User@Example.com ",
		Username: "fallback",
	})
	if err != nil {
		t.Fatalf("getUser returned error: %v", err)
	}
	if user.ID != 1 {
		t.Fatalf("user.ID = %d, want 1", user.ID)
	}
}
