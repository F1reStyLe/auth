package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type TokenManager interface {
	Generate(tokenExpiration time.Duration, userID int64) (string, error)
}

type Service struct {
	repo            Repository
	tokens          TokenManager
	tokenExpiration time.Duration
	refreshTokenTTL time.Duration
	verifyTokenTTL  time.Duration
	resetTokenTTL   time.Duration
}

func NewService(
	repo Repository,
	tokens TokenManager,
	tokenExpiration time.Duration,
	refreshTokenTTL time.Duration,
	verifyTokenTTL time.Duration,
	resetTokenTTL time.Duration,
) *Service {
	return &Service{
		repo:            repo,
		tokens:          tokens,
		tokenExpiration: tokenExpiration,
		refreshTokenTTL: refreshTokenTTL,
		verifyTokenTTL:  verifyTokenTTL,
		resetTokenTTL:   resetTokenTTL,
	}
}

func getHash(pwd []byte) (string, error) {
	hash, err := bcrypt.GenerateFromPassword(pwd, bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func generateOpaqueToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate random token: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func (s *Service) Register(ctx context.Context, req RegisterRequest) (*RegisterResponse, error) {
	hash, err := getHash([]byte(req.Password))
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	user, err := s.repo.CreateUser(ctx, CreateUserParams{
		Email:        strings.TrimSpace(strings.ToLower(req.Email)),
		Username:     strings.TrimSpace(req.Username),
		PasswordHash: hash,
	})
	if err != nil {
		return nil, err
	}

	token, tokenResp, err := s.issueOneTimeToken(ctx, user.ID, tokenPurposeVerifyEmail, s.verifyTokenTTL)
	if err != nil {
		return nil, err
	}

	_ = token

	return &RegisterResponse{
		Status:                "created",
		VerificationToken:     tokenResp.Token,
		VerificationExpiresAt: tokenResp.ExpiresAt,
	}, nil
}

func getUser(s *Service, ctx context.Context, req LoginRequest) (*User, error) {
	if email := strings.TrimSpace(strings.ToLower(req.Email)); email != "" {
		return s.repo.GetUserByEmail(ctx, email)
	}

	if username := strings.TrimSpace(req.Username); username != "" {
		return s.repo.GetUserByUsername(ctx, username)
	}

	return nil, ErrInvalidCredentials
}

func (s *Service) Login(ctx context.Context, req LoginRequest) (*TokenResponse, error) {
	user, err := getUser(s, ctx, req)
	if err != nil {
		return nil, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		return nil, ErrInvalidCredentials
	}
	if user.EmailVerifiedAt == nil {
		return nil, ErrEmailNotVerified
	}

	return s.issueSession(ctx, user.ID)
}

func (s *Service) Refresh(ctx context.Context, req RefreshTokenRequest) (*TokenResponse, error) {
	refreshToken := strings.TrimSpace(req.RefreshToken)
	if refreshToken == "" {
		return nil, ErrInvalidToken
	}

	session, err := s.repo.GetSessionByTokenHash(ctx, hashToken(refreshToken))
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	if session.RevokedAt != nil {
		return nil, ErrInvalidToken
	}
	if now.After(session.ExpiresAt) {
		return nil, ErrTokenExpired
	}

	newRefreshToken, err := generateOpaqueToken()
	if err != nil {
		return nil, err
	}

	rotatedSession, err := s.repo.RotateSessionToken(
		ctx,
		session.ID,
		hashToken(newRefreshToken),
		now.Add(s.refreshTokenTTL),
		now,
	)
	if err != nil {
		return nil, err
	}

	accessToken, err := s.tokens.Generate(s.tokenExpiration, rotatedSession.UserID)
	if err != nil {
		return nil, fmt.Errorf("generate access token: %w", err)
	}

	return &TokenResponse{
		AccessToken:           accessToken,
		AccessTokenExpiresAt:  now.Add(s.tokenExpiration),
		RefreshToken:          newRefreshToken,
		RefreshTokenExpiresAt: rotatedSession.ExpiresAt,
	}, nil
}

func (s *Service) Logout(ctx context.Context, req LogoutRequest) error {
	refreshToken := strings.TrimSpace(req.RefreshToken)
	if refreshToken == "" {
		return ErrInvalidToken
	}

	return s.repo.RevokeSessionByTokenHash(ctx, hashToken(refreshToken), time.Now().UTC())
}

func (s *Service) RequestEmailVerification(ctx context.Context, req RequestEmailVerificationRequest) (*OneTimeTokenResponse, error) {
	email := strings.TrimSpace(strings.ToLower(req.Email))
	if email == "" {
		return &OneTimeTokenResponse{Status: "accepted"}, nil
	}

	user, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		if err == ErrInvalidCredentials {
			return &OneTimeTokenResponse{Status: "accepted"}, nil
		}
		return nil, err
	}

	if user.EmailVerifiedAt != nil {
		return &OneTimeTokenResponse{Status: "accepted"}, nil
	}

	_, resp, err := s.issueOneTimeToken(ctx, user.ID, tokenPurposeVerifyEmail, s.verifyTokenTTL)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (s *Service) VerifyEmail(ctx context.Context, req VerifyEmailRequest) error {
	token, err := s.consumeOneTimeToken(ctx, req.Token, tokenPurposeVerifyEmail)
	if err != nil {
		return err
	}

	if err := s.repo.MarkUserEmailVerified(ctx, token.UserID, time.Now().UTC()); err != nil {
		return err
	}

	return nil
}

func (s *Service) RequestPasswordReset(ctx context.Context, req RequestPasswordResetRequest) (*OneTimeTokenResponse, error) {
	email := strings.TrimSpace(strings.ToLower(req.Email))
	if email == "" {
		return &OneTimeTokenResponse{Status: "accepted"}, nil
	}

	user, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		if err == ErrInvalidCredentials {
			return &OneTimeTokenResponse{Status: "accepted"}, nil
		}
		return nil, err
	}

	_, resp, err := s.issueOneTimeToken(ctx, user.ID, tokenPurposeResetPassword, s.resetTokenTTL)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (s *Service) ResetPassword(ctx context.Context, req ResetPasswordRequest) error {
	token, err := s.consumeOneTimeToken(ctx, req.Token, tokenPurposeResetPassword)
	if err != nil {
		return err
	}

	passwordHash, err := getHash([]byte(req.NewPassword))
	if err != nil {
		return fmt.Errorf("hash new password: %w", err)
	}

	if err := s.repo.UpdatePasswordHash(ctx, token.UserID, passwordHash); err != nil {
		return err
	}

	if err := s.repo.RevokeAllUserSessions(ctx, token.UserID, time.Now().UTC()); err != nil {
		return err
	}

	return nil
}

func (s *Service) Me(ctx context.Context, userID int64) (*User, error) {
	return s.repo.GetUserByID(ctx, userID)
}

func (s *Service) issueSession(ctx context.Context, userID int64) (*TokenResponse, error) {
	now := time.Now().UTC()

	accessToken, err := s.tokens.Generate(s.tokenExpiration, userID)
	if err != nil {
		return nil, fmt.Errorf("generate access token: %w", err)
	}

	refreshToken, err := generateOpaqueToken()
	if err != nil {
		return nil, err
	}

	session, err := s.repo.CreateSession(ctx, CreateSessionParams{
		UserID:    userID,
		TokenHash: hashToken(refreshToken),
		ExpiresAt: now.Add(s.refreshTokenTTL),
	})
	if err != nil {
		return nil, err
	}

	return &TokenResponse{
		AccessToken:           accessToken,
		AccessTokenExpiresAt:  now.Add(s.tokenExpiration),
		RefreshToken:          refreshToken,
		RefreshTokenExpiresAt: session.ExpiresAt,
	}, nil
}

func (s *Service) issueOneTimeToken(ctx context.Context, userID int64, purpose string, ttl time.Duration) (string, *OneTimeTokenResponse, error) {
	rawToken, err := generateOpaqueToken()
	if err != nil {
		return "", nil, err
	}

	expiresAt := time.Now().UTC().Add(ttl)
	if _, err := s.repo.ReplaceOneTimeToken(ctx, CreateOneTimeTokenParams{
		UserID:    userID,
		Purpose:   purpose,
		TokenHash: hashToken(rawToken),
		ExpiresAt: expiresAt,
	}); err != nil {
		return "", nil, err
	}

	return rawToken, &OneTimeTokenResponse{
		Status:    "accepted",
		Token:     rawToken,
		ExpiresAt: expiresAt,
	}, nil
}

func (s *Service) consumeOneTimeToken(ctx context.Context, rawToken string, purpose string) (*OneTimeToken, error) {
	token, err := s.repo.GetValidOneTimeToken(ctx, purpose, hashToken(strings.TrimSpace(rawToken)))
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	if token.ConsumedAt != nil {
		return nil, ErrInvalidToken
	}
	if now.After(token.ExpiresAt) {
		return nil, ErrTokenExpired
	}

	if err := s.repo.ConsumeOneTimeToken(ctx, token.ID, now); err != nil {
		return nil, err
	}

	return token, nil
}
