package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type repositoryMock struct {
	createUserFn            func(context.Context, CreateUserParams) (*User, error)
	getUserByIDFn           func(context.Context, int64) (*User, error)
	getUserByUsernameFn     func(context.Context, string) (*User, error)
	getUserByEmailFn        func(context.Context, string) (*User, error)
	getUserProfileFn        func(context.Context, int64) (*UserProfile, error)
	upsertUserProfileFn     func(context.Context, UserProfile) (*UserProfile, error)
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
	getOAuthAccountFn       func(context.Context, OAuthProvider, string) (*OAuthAccount, error)
	createOAuthAccountFn    func(context.Context, CreateOAuthAccountParams) (*OAuthAccount, error)
	updateUserRoleFn        func(context.Context, int64, Role) error
	updateAccountStatusFn   func(context.Context, int64, AccountStatus) error
	createAuditLogFn        func(context.Context, CreateAuditLogParams) error
}

func (m *repositoryMock) CreateUser(ctx context.Context, params CreateUserParams) (*User, error) {
	if m.createUserFn == nil {
		return nil, nil
	}
	return m.createUserFn(ctx, params)
}

func (m *repositoryMock) GetUserByID(ctx context.Context, id int64) (*User, error) {
	if m.getUserByIDFn == nil {
		return nil, nil
	}
	return m.getUserByIDFn(ctx, id)
}

func (m *repositoryMock) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	if m.getUserByUsernameFn == nil {
		return nil, nil
	}
	return m.getUserByUsernameFn(ctx, username)
}

func (m *repositoryMock) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	if m.getUserByEmailFn == nil {
		return nil, nil
	}
	return m.getUserByEmailFn(ctx, email)
}

func (m *repositoryMock) GetUserProfile(ctx context.Context, userID int64) (*UserProfile, error) {
	if m.getUserProfileFn == nil {
		return nil, nil
	}
	return m.getUserProfileFn(ctx, userID)
}

func (m *repositoryMock) UpsertUserProfile(ctx context.Context, profile UserProfile) (*UserProfile, error) {
	if m.upsertUserProfileFn == nil {
		return &profile, nil
	}
	return m.upsertUserProfileFn(ctx, profile)
}

func (m *repositoryMock) CreateSession(ctx context.Context, params CreateSessionParams) (*Session, error) {
	if m.createSessionFn == nil {
		return nil, nil
	}
	return m.createSessionFn(ctx, params)
}

func (m *repositoryMock) GetSessionByTokenHash(ctx context.Context, tokenHash string) (*Session, error) {
	if m.getSessionByTokenHashFn == nil {
		return nil, nil
	}
	return m.getSessionByTokenHashFn(ctx, tokenHash)
}

func (m *repositoryMock) RotateSessionToken(ctx context.Context, sessionID int64, tokenHash string, expiresAt time.Time, lastUsedAt time.Time) (*Session, error) {
	if m.rotateSessionTokenFn == nil {
		return nil, nil
	}
	return m.rotateSessionTokenFn(ctx, sessionID, tokenHash, expiresAt, lastUsedAt)
}

func (m *repositoryMock) RevokeSessionByTokenHash(ctx context.Context, tokenHash string, revokedAt time.Time) error {
	if m.revokeSessionByHashFn == nil {
		return nil
	}
	return m.revokeSessionByHashFn(ctx, tokenHash, revokedAt)
}

func (m *repositoryMock) RevokeAllUserSessions(ctx context.Context, userID int64, revokedAt time.Time) error {
	if m.revokeAllSessionsFn == nil {
		return nil
	}
	return m.revokeAllSessionsFn(ctx, userID, revokedAt)
}

func (m *repositoryMock) CreateOneTimeToken(ctx context.Context, params CreateOneTimeTokenParams) (*OneTimeToken, error) {
	if m.createOneTimeTokenFn == nil {
		return nil, nil
	}
	return m.createOneTimeTokenFn(ctx, params)
}

func (m *repositoryMock) GetValidOneTimeToken(ctx context.Context, purpose, tokenHash string) (*OneTimeToken, error) {
	if m.getValidTokenFn == nil {
		return nil, nil
	}
	return m.getValidTokenFn(ctx, purpose, tokenHash)
}

func (m *repositoryMock) ConsumeOneTimeToken(ctx context.Context, tokenID int64, consumedAt time.Time) error {
	if m.consumeOneTimeTokenFn == nil {
		return nil
	}
	return m.consumeOneTimeTokenFn(ctx, tokenID, consumedAt)
}

func (m *repositoryMock) ReplaceOneTimeToken(ctx context.Context, params CreateOneTimeTokenParams) (*OneTimeToken, error) {
	if m.replaceOneTimeTokenFn == nil {
		return nil, nil
	}
	return m.replaceOneTimeTokenFn(ctx, params)
}

func (m *repositoryMock) MarkUserEmailVerified(ctx context.Context, userID int64, verifiedAt time.Time) error {
	if m.markEmailVerifiedFn == nil {
		return nil
	}
	return m.markEmailVerifiedFn(ctx, userID, verifiedAt)
}

func (m *repositoryMock) UpdatePasswordHash(ctx context.Context, userID int64, passwordHash string) error {
	if m.updatePasswordHashFn == nil {
		return nil
	}
	return m.updatePasswordHashFn(ctx, userID, passwordHash)
}

func (m *repositoryMock) GetOAuthAccount(ctx context.Context, provider OAuthProvider, providerUserID string) (*OAuthAccount, error) {
	if m.getOAuthAccountFn == nil {
		return nil, ErrUnauthorized
	}
	return m.getOAuthAccountFn(ctx, provider, providerUserID)
}

func (m *repositoryMock) CreateOAuthAccount(ctx context.Context, params CreateOAuthAccountParams) (*OAuthAccount, error) {
	if m.createOAuthAccountFn == nil {
		return nil, nil
	}
	return m.createOAuthAccountFn(ctx, params)
}

func (m *repositoryMock) UpdateUserRole(ctx context.Context, userID int64, role Role) error {
	if m.updateUserRoleFn == nil {
		return nil
	}
	return m.updateUserRoleFn(ctx, userID, role)
}

func (m *repositoryMock) UpdateAccountStatus(ctx context.Context, userID int64, status AccountStatus) error {
	if m.updateAccountStatusFn == nil {
		return nil
	}
	return m.updateAccountStatusFn(ctx, userID, status)
}

func (m *repositoryMock) CreateAuditLog(ctx context.Context, params CreateAuditLogParams) error {
	if m.createAuditLogFn == nil {
		return nil
	}
	return m.createAuditLogFn(ctx, params)
}

type tokenManagerMock struct {
	generateFn func(time.Duration, int64) (string, error)
}

func (m tokenManagerMock) Generate(exp time.Duration, userID int64) (string, error) {
	return m.generateFn(exp, userID)
}

type notifierMock struct {
	sendEmailVerificationFn func(context.Context, string, string, time.Time) error
	sendPasswordResetFn     func(context.Context, string, string, time.Time) error
}

func (m notifierMock) SendEmailVerification(ctx context.Context, email, url string, expiresAt time.Time) error {
	if m.sendEmailVerificationFn == nil {
		return nil
	}
	return m.sendEmailVerificationFn(ctx, email, url, expiresAt)
}

func (m notifierMock) SendPasswordReset(ctx context.Context, email, url string, expiresAt time.Time) error {
	if m.sendPasswordResetFn == nil {
		return nil
	}
	return m.sendPasswordResetFn(ctx, email, url, expiresAt)
}

type oauthProviderMock struct {
	authCodeURLFn func(state string) string
	exchangeFn    func(context.Context, string) (*OAuthIdentity, error)
}

func (m oauthProviderMock) AuthCodeURL(state string) string {
	return m.authCodeURLFn(state)
}

func (m oauthProviderMock) Exchange(ctx context.Context, code string) (*OAuthIdentity, error) {
	return m.exchangeFn(ctx, code)
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
		nil,
		15*time.Minute,
		24*time.Hour,
		24*time.Hour,
		time.Hour,
		"test-secret",
		"https://app.example.com",
		nil,
	)

	_, err = svc.Login(context.Background(), LoginRequest{
		Email:    "user@example.com",
		Password: "secret",
	})
	if !errors.Is(err, ErrEmailNotVerified) {
		t.Fatalf("Login error = %v, want %v", err, ErrEmailNotVerified)
	}
}

func TestServiceLoginBlockedAccount(t *testing.T) {
	t.Parallel()

	passwordHash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword: %v", err)
	}
	verifiedAt := time.Now().UTC()

	svc := NewService(
		&repositoryMock{
			getUserByEmailFn: func(context.Context, string) (*User, error) {
				return &User{
					ID:              7,
					Email:           "user@example.com",
					PasswordHash:    string(passwordHash),
					EmailVerifiedAt: &verifiedAt,
					AccountStatus:   AccountStatusBlocked,
				}, nil
			},
		},
		tokenManagerMock{generateFn: func(time.Duration, int64) (string, error) { return "", errors.New("unexpected token generation") }},
		nil,
		15*time.Minute,
		24*time.Hour,
		24*time.Hour,
		time.Hour,
		"test-secret",
		"https://app.example.com",
		nil,
	)

	_, err = svc.Login(context.Background(), LoginRequest{
		Email:    "user@example.com",
		Password: "secret",
	})
	if !errors.Is(err, ErrAccountBlocked) {
		t.Fatalf("Login error = %v, want %v", err, ErrAccountBlocked)
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
			getUserByIDFn: func(_ context.Context, id int64) (*User, error) {
				if id != 42 {
					t.Fatalf("GetUserByID id = %d, want 42", id)
				}
				return &User{ID: 42, AccountStatus: AccountStatusActive}, nil
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
		nil,
		15*time.Minute,
		24*time.Hour,
		24*time.Hour,
		time.Hour,
		"test-secret",
		"https://app.example.com",
		nil,
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
		nil,
		15*time.Minute,
		24*time.Hour,
		24*time.Hour,
		time.Hour,
		"test-secret",
		"https://app.example.com",
		nil,
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
		nil,
		15*time.Minute,
		24*time.Hour,
		24*time.Hour,
		time.Hour,
		"test-secret",
		"https://app.example.com",
		nil,
	)

	if err := svc.ResetPassword(context.Background(), ResetPasswordRequest{
		Token:       rawToken,
		NewPassword: "NewStrongPass123!",
	}); err != nil {
		t.Fatalf("ResetPassword returned error: %v", err)
	}
	if updatedHash == "" {
		t.Fatal("expected password hash to be updated")
	}
	if bcrypt.CompareHashAndPassword([]byte(updatedHash), []byte("NewStrongPass123!")) != nil {
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
		nil,
		15*time.Minute,
		24*time.Hour,
		24*time.Hour,
		time.Hour,
		"test-secret",
		"https://app.example.com",
		nil,
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
		nil,
		15*time.Minute,
		24*time.Hour,
		24*time.Hour,
		time.Hour,
		"test-secret",
		"https://app.example.com",
		nil,
	)

	resp, err := svc.RequestPasswordReset(context.Background(), RequestPasswordResetRequest{Email: "missing@example.com"})
	if err != nil {
		t.Fatalf("RequestPasswordReset returned error: %v", err)
	}
	if resp.Status != "accepted" {
		t.Fatalf("status = %q, want %q", resp.Status, "accepted")
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
		nil,
		15*time.Minute,
		24*time.Hour,
		24*time.Hour,
		time.Hour,
		"test-secret",
		"https://app.example.com",
		nil,
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

func TestServiceOAuthStartBuildsProviderURL(t *testing.T) {
	t.Parallel()

	svc := NewService(
		&repositoryMock{},
		tokenManagerMock{generateFn: func(time.Duration, int64) (string, error) { return "", nil }},
		nil,
		15*time.Minute,
		24*time.Hour,
		24*time.Hour,
		time.Hour,
		"test-secret",
		"https://app.example.com",
		map[OAuthProvider]OAuthProviderClient{
			OAuthProviderGoogle: oauthProviderMock{
				authCodeURLFn: func(state string) string {
					if state == "" {
						t.Fatal("expected non-empty state")
					}
					return "https://accounts.example/auth?state=" + state
				},
				exchangeFn: func(context.Context, string) (*OAuthIdentity, error) { return nil, nil },
			},
		},
	)

	resp, err := svc.OAuthStart(context.Background(), OAuthProviderGoogle)
	if err != nil {
		t.Fatalf("OAuthStart returned error: %v", err)
	}
	if resp.Provider != OAuthProviderGoogle {
		t.Fatalf("provider = %q, want %q", resp.Provider, OAuthProviderGoogle)
	}
	if resp.AuthorizationURL == "" || resp.State == "" {
		t.Fatal("expected authorization url and state to be set")
	}
}

func TestServiceRegisterSendsVerificationEmail(t *testing.T) {
	t.Parallel()

	var sentURL string

	svc := NewService(
		&repositoryMock{
			createUserFn: func(_ context.Context, params CreateUserParams) (*User, error) {
				return &User{
					ID:              9,
					Email:           params.Email,
					Username:        params.Username,
					AccountStatus:   AccountStatusActive,
					EmailVerifiedAt: nil,
				}, nil
			},
			upsertUserProfileFn: func(_ context.Context, profile UserProfile) (*UserProfile, error) {
				return &profile, nil
			},
			replaceOneTimeTokenFn: func(_ context.Context, params CreateOneTimeTokenParams) (*OneTimeToken, error) {
				return &OneTimeToken{
					ID:        1,
					UserID:    params.UserID,
					Purpose:   params.Purpose,
					TokenHash: params.TokenHash,
					ExpiresAt: params.ExpiresAt,
				}, nil
			},
		},
		tokenManagerMock{generateFn: func(time.Duration, int64) (string, error) { return "", nil }},
		notifierMock{
			sendEmailVerificationFn: func(_ context.Context, email, verificationURL string, _ time.Time) error {
				if email != "user@example.com" {
					t.Fatalf("email = %q, want normalized email", email)
				}
				sentURL = verificationURL
				return nil
			},
		},
		15*time.Minute,
		24*time.Hour,
		24*time.Hour,
		time.Hour,
		"test-secret",
		"https://app.example.com",
		nil,
	)

	resp, err := svc.Register(context.Background(), RegisterRequest{
		Email:    " User@Example.com ",
		Username: "user.name",
		Password: "StrongPass123!",
	})
	if err != nil {
		t.Fatalf("Register returned error: %v", err)
	}
	if resp.Status != "created" {
		t.Fatalf("status = %q, want created", resp.Status)
	}
	if !strings.HasPrefix(sentURL, "https://app.example.com/verify-email?token=") {
		t.Fatalf("verification url = %q, want app verify-email URL", sentURL)
	}
}

func TestServiceRequestPasswordResetSendsResetEmail(t *testing.T) {
	t.Parallel()

	var sentURL string

	svc := NewService(
		&repositoryMock{
			getUserByEmailFn: func(_ context.Context, email string) (*User, error) {
				return &User{ID: 17, Email: email}, nil
			},
			replaceOneTimeTokenFn: func(_ context.Context, params CreateOneTimeTokenParams) (*OneTimeToken, error) {
				return &OneTimeToken{
					ID:        2,
					UserID:    params.UserID,
					Purpose:   params.Purpose,
					TokenHash: params.TokenHash,
					ExpiresAt: params.ExpiresAt,
				}, nil
			},
		},
		tokenManagerMock{generateFn: func(time.Duration, int64) (string, error) { return "", nil }},
		notifierMock{
			sendPasswordResetFn: func(_ context.Context, email, resetURL string, _ time.Time) error {
				if email != "user@example.com" {
					t.Fatalf("email = %q, want normalized email", email)
				}
				sentURL = resetURL
				return nil
			},
		},
		15*time.Minute,
		24*time.Hour,
		24*time.Hour,
		time.Hour,
		"test-secret",
		"https://app.example.com",
		nil,
	)

	resp, err := svc.RequestPasswordReset(context.Background(), RequestPasswordResetRequest{Email: "user@example.com"})
	if err != nil {
		t.Fatalf("RequestPasswordReset returned error: %v", err)
	}
	if resp.Status != "accepted" {
		t.Fatalf("status = %q, want accepted", resp.Status)
	}
	if !strings.HasPrefix(sentURL, "https://app.example.com/reset-password?token=") {
		t.Fatalf("reset url = %q, want app reset-password URL", sentURL)
	}
}
