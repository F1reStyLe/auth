package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
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
	stateSecret     []byte
	oauthProviders  map[OAuthProvider]OAuthProviderClient
}

func NewService(
	repo Repository,
	tokens TokenManager,
	tokenExpiration time.Duration,
	refreshTokenTTL time.Duration,
	verifyTokenTTL time.Duration,
	resetTokenTTL time.Duration,
	stateSecret string,
	oauthProviders map[OAuthProvider]OAuthProviderClient,
) *Service {
	return &Service{
		repo:            repo,
		tokens:          tokens,
		tokenExpiration: tokenExpiration,
		refreshTokenTTL: refreshTokenTTL,
		verifyTokenTTL:  verifyTokenTTL,
		resetTokenTTL:   resetTokenTTL,
		stateSecret:     []byte(stateSecret),
		oauthProviders:  oauthProviders,
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
		Email:         strings.TrimSpace(strings.ToLower(req.Email)),
		Username:      strings.TrimSpace(req.Username),
		PasswordHash:  hash,
		Role:          RoleUser,
		AccountStatus: AccountStatusActive,
	})
	if err != nil {
		return nil, err
	}

	if _, err := s.repo.UpsertUserProfile(ctx, UserProfile{
		UserID:   user.ID,
		FullName: strings.TrimSpace(req.Username),
		Timezone: "UTC",
	}); err != nil {
		return nil, err
	}

	_, tokenResp, err := s.issueOneTimeToken(ctx, user.ID, tokenPurposeVerifyEmail, s.verifyTokenTTL)
	if err != nil {
		return nil, err
	}

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
	if err := ensureUserAvailable(user); err != nil {
		return nil, err
	}
	if user.EmailVerifiedAt == nil {
		return nil, ErrEmailNotVerified
	}

	resp, err := s.issueSession(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	if err := s.repo.CreateAuditLog(ctx, CreateAuditLogParams{
		UserID:  &user.ID,
		Action:  AuditActionLoginSucceeded,
		Details: map[string]any{"method": "password"},
	}); err != nil {
		return nil, err
	}
	return resp, nil
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

	user, err := s.repo.GetUserByID(ctx, session.UserID)
	if err != nil {
		return nil, err
	}
	if err := ensureUserAvailable(user); err != nil {
		return nil, err
	}

	newRefreshToken, err := generateOpaqueToken()
	if err != nil {
		return nil, err
	}

	rotatedSession, err := s.repo.RotateSessionToken(ctx, session.ID, hashToken(newRefreshToken), now.Add(s.refreshTokenTTL), now)
	if err != nil {
		return nil, err
	}

	accessToken, err := s.tokens.Generate(s.tokenExpiration, rotatedSession.UserID)
	if err != nil {
		return nil, fmt.Errorf("generate access token: %w", err)
	}
	if err := s.repo.CreateAuditLog(ctx, CreateAuditLogParams{
		UserID:  &user.ID,
		Action:  AuditActionTokenIssued,
		Details: map[string]any{"method": "refresh"},
	}); err != nil {
		return nil, err
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
		if errorsIsCredentialLookup(err) {
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
	return s.repo.MarkUserEmailVerified(ctx, token.UserID, time.Now().UTC())
}

func (s *Service) RequestPasswordReset(ctx context.Context, req RequestPasswordResetRequest) (*OneTimeTokenResponse, error) {
	email := strings.TrimSpace(strings.ToLower(req.Email))
	if email == "" {
		return &OneTimeTokenResponse{Status: "accepted"}, nil
	}
	user, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		if errorsIsCredentialLookup(err) {
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
	if err := s.repo.CreateAuditLog(ctx, CreateAuditLogParams{
		UserID: &token.UserID,
		Action: AuditActionPasswordChanged,
	}); err != nil {
		return err
	}
	return nil
}

func (s *Service) GetMe(ctx context.Context, userID int64) (*UserProfileResponse, error) {
	return s.userResponse(ctx, userID)
}

func (s *Service) UpdateMyProfile(ctx context.Context, userID int64, req UpdateProfileRequest) (*UserProfileResponse, error) {
	if _, err := s.repo.UpsertUserProfile(ctx, UserProfile{
		UserID:    userID,
		FullName:  strings.TrimSpace(req.FullName),
		AvatarURL: strings.TrimSpace(req.AvatarURL),
		Status:    strings.TrimSpace(req.Status),
		Timezone:  strings.TrimSpace(req.Timezone),
	}); err != nil {
		return nil, err
	}
	return s.userResponse(ctx, userID)
}

func (s *Service) UpdateUserRole(ctx context.Context, actorID, targetUserID int64, role Role) error {
	actor, err := s.repo.GetUserByID(ctx, actorID)
	if err != nil {
		return err
	}
	if actor.Role != RoleAdmin {
		return ErrForbidden
	}
	if role != RoleUser && role != RoleModerator && role != RoleAdmin {
		return ErrForbidden
	}
	if err := s.repo.UpdateUserRole(ctx, targetUserID, role); err != nil {
		return err
	}
	if err := s.repo.CreateAuditLog(ctx, CreateAuditLogParams{
		UserID:      &targetUserID,
		ActorUserID: &actorID,
		Action:      AuditActionRoleChanged,
		Details:     map[string]any{"role": role},
	}); err != nil {
		return err
	}
	return nil
}

func (s *Service) UpdateUserStatus(ctx context.Context, actorID, targetUserID int64, status AccountStatus) error {
	actor, err := s.repo.GetUserByID(ctx, actorID)
	if err != nil {
		return err
	}
	if actor.Role != RoleAdmin && actor.Role != RoleModerator {
		return ErrForbidden
	}
	if status != AccountStatusActive && status != AccountStatusBlocked && status != AccountStatusDeactivated {
		return ErrForbidden
	}
	if err := s.repo.UpdateAccountStatus(ctx, targetUserID, status); err != nil {
		return err
	}
	if status == AccountStatusBlocked || status == AccountStatusDeactivated {
		if err := s.repo.RevokeAllUserSessions(ctx, targetUserID, time.Now().UTC()); err != nil {
			return err
		}
	}
	action := AuditActionAccountBlocked
	if status == AccountStatusDeactivated {
		action = AuditActionAccountDeactivated
	}
	if status == AccountStatusActive {
		action = AuditActionAccountStatusChanged
	}
	return s.repo.CreateAuditLog(ctx, CreateAuditLogParams{
		UserID:      &targetUserID,
		ActorUserID: &actorID,
		Action:      action,
		Details:     map[string]any{"status": status},
	})
}

func (s *Service) OAuthStart(ctx context.Context, provider OAuthProvider) (*OAuthStartResponse, error) {
	client, ok := s.oauthProviders[provider]
	if !ok || client == nil {
		return nil, ErrOAuthNotConfigured
	}
	state, err := s.signOAuthState(provider)
	if err != nil {
		return nil, err
	}
	return &OAuthStartResponse{
		Provider:         provider,
		AuthorizationURL: client.AuthCodeURL(state),
		State:            state,
	}, nil
}

func (s *Service) OAuthCallback(ctx context.Context, provider OAuthProvider, code, state string) (*OAuthCallbackResponse, error) {
	client, ok := s.oauthProviders[provider]
	if !ok || client == nil {
		return nil, ErrOAuthNotConfigured
	}
	if err := s.verifyOAuthState(provider, state); err != nil {
		return nil, err
	}
	identity, err := client.Exchange(ctx, strings.TrimSpace(code))
	if err != nil {
		return nil, err
	}
	user, err := s.resolveOAuthUser(ctx, identity)
	if err != nil {
		return nil, err
	}
	if err := ensureUserAvailable(user); err != nil {
		return nil, err
	}

	resp, err := s.issueSession(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	if err := s.repo.CreateAuditLog(ctx, CreateAuditLogParams{
		UserID:  &user.ID,
		Action:  AuditActionOAuthLogin,
		Details: map[string]any{"provider": provider},
	}); err != nil {
		return nil, err
	}
	userResp, err := s.userResponse(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	return &OAuthCallbackResponse{
		User:   userResp,
		Tokens: resp,
	}, nil
}

func (s *Service) resolveOAuthUser(ctx context.Context, identity *OAuthIdentity) (*User, error) {
	if account, err := s.repo.GetOAuthAccount(ctx, identity.Provider, identity.ProviderUserID); err == nil {
		user, err := s.repo.GetUserByID(ctx, account.UserID)
		if err != nil {
			return nil, err
		}
		_, _ = s.repo.UpsertUserProfile(ctx, UserProfile{
			UserID:    user.ID,
			FullName:  identity.FullName,
			AvatarURL: identity.AvatarURL,
			Timezone:  "UTC",
		})
		return user, nil
	}

	var user *User
	var err error
	if identity.Email != "" {
		user, err = s.repo.GetUserByEmail(ctx, identity.Email)
		if err != nil && !errorsIsCredentialLookup(err) {
			return nil, err
		}
	}

	if user == nil {
		now := time.Now().UTC()
		emailVerifiedAt := (*time.Time)(nil)
		if identity.EmailVerified {
			emailVerifiedAt = &now
		}
		user, err = s.repo.CreateUser(ctx, CreateUserParams{
			Email:           identity.Email,
			Username:        s.uniqueUsername(ctx, identity),
			PasswordHash:    "",
			EmailVerifiedAt: emailVerifiedAt,
			Role:            RoleUser,
			AccountStatus:   AccountStatusActive,
		})
		if err != nil {
			return nil, err
		}
	}

	if _, err := s.repo.CreateOAuthAccount(ctx, CreateOAuthAccountParams{
		UserID:         user.ID,
		Provider:       identity.Provider,
		ProviderUserID: identity.ProviderUserID,
	}); err != nil {
		return nil, err
	}

	_, err = s.repo.UpsertUserProfile(ctx, UserProfile{
		UserID:    user.ID,
		FullName:  identity.FullName,
		AvatarURL: identity.AvatarURL,
		Timezone:  "UTC",
	})
	if err != nil {
		return nil, err
	}

	return s.repo.GetUserByID(ctx, user.ID)
}

func (s *Service) uniqueUsername(ctx context.Context, identity *OAuthIdentity) string {
	base := strings.TrimSpace(identity.Username)
	if base == "" {
		base = usernameFromEmail(identity.Email)
	}
	if base == "" {
		base = fmt.Sprintf("%s_user", identity.Provider)
	}
	candidate := base
	for i := 0; i < 5; i++ {
		_, err := s.repo.GetUserByUsername(ctx, candidate)
		if errorsIsCredentialLookup(err) {
			return candidate
		}
		candidate = fmt.Sprintf("%s_%d", base, time.Now().Unix())
	}
	return candidate
}

func (s *Service) userResponse(ctx context.Context, userID int64) (*UserProfileResponse, error) {
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	profile, err := s.repo.GetUserProfile(ctx, userID)
	if err != nil {
		return nil, err
	}
	return &UserProfileResponse{
		ID:              user.ID,
		Username:        user.Username,
		Email:           user.Email,
		EmailVerifiedAt: user.EmailVerifiedAt,
		Role:            user.Role,
		AccountStatus:   user.AccountStatus,
		Profile:         *profile,
	}, nil
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
	if err := s.repo.CreateAuditLog(ctx, CreateAuditLogParams{
		UserID:  &userID,
		Action:  AuditActionTokenIssued,
		Details: map[string]any{"method": "issue_session"},
	}); err != nil {
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

func (s *Service) consumeOneTimeToken(ctx context.Context, rawToken, purpose string) (*OneTimeToken, error) {
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

type oauthStatePayload struct {
	Provider OAuthProvider `json:"provider"`
	Expires  int64         `json:"exp"`
}

func (s *Service) signOAuthState(provider OAuthProvider) (string, error) {
	payload := oauthStatePayload{
		Provider: provider,
		Expires:  time.Now().UTC().Add(10 * time.Minute).Unix(),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal oauth state: %w", err)
	}
	bodyPart := base64.RawURLEncoding.EncodeToString(body)
	mac := hmac.New(sha256.New, s.stateSecret)
	_, _ = mac.Write([]byte(bodyPart))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return bodyPart + "." + signature, nil
}

func (s *Service) verifyOAuthState(provider OAuthProvider, state string) error {
	bodyPart, sigPart, ok := strings.Cut(strings.TrimSpace(state), ".")
	if !ok {
		return ErrInvalidOAuthState
	}
	mac := hmac.New(sha256.New, s.stateSecret)
	_, _ = mac.Write([]byte(bodyPart))
	expected := mac.Sum(nil)
	given, err := base64.RawURLEncoding.DecodeString(sigPart)
	if err != nil || !hmac.Equal(expected, given) {
		return ErrInvalidOAuthState
	}
	body, err := base64.RawURLEncoding.DecodeString(bodyPart)
	if err != nil {
		return ErrInvalidOAuthState
	}
	var payload oauthStatePayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return ErrInvalidOAuthState
	}
	if payload.Provider != provider || time.Now().UTC().Unix() > payload.Expires {
		return ErrInvalidOAuthState
	}
	return nil
}

func ensureUserAvailable(user *User) error {
	switch user.AccountStatus {
	case AccountStatusBlocked:
		return ErrAccountBlocked
	case AccountStatusDeactivated:
		return ErrAccountDeactivated
	default:
		return nil
	}
}

func errorsIsCredentialLookup(err error) bool {
	return err != nil && (strings.Contains(err.Error(), ErrInvalidCredentials.Error()) || strings.Contains(err.Error(), ErrUnauthorized.Error()) || err == ErrInvalidCredentials || err == ErrUnauthorized)
}
