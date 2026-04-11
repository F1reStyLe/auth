package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

const (
	tokenPurposeVerifyEmail   = "verify_email"
	tokenPurposeResetPassword = "reset_password"
	tokenPurposeOAuthGoogle   = "oauth_google"
	tokenPurposeOAuthGitHub   = "oauth_github"
)

type CreateUserParams struct {
	Email           string
	Username        string
	PasswordHash    string
	EmailVerifiedAt *time.Time
	Role            Role
	AccountStatus   AccountStatus
}

type CreateSessionParams struct {
	UserID    int64
	TokenHash string
	ExpiresAt time.Time
}

type CreateOneTimeTokenParams struct {
	UserID    int64
	Purpose   string
	TokenHash string
	ExpiresAt time.Time
}

type CreateOAuthAccountParams struct {
	UserID         int64
	Provider       OAuthProvider
	ProviderUserID string
}

type CreateAuditLogParams struct {
	UserID      *int64
	ActorUserID *int64
	Action      AuditAction
	Details     map[string]any
}

type Repository interface {
	CreateUser(ctx context.Context, params CreateUserParams) (*User, error)
	GetUserByID(ctx context.Context, id int64) (*User, error)
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	GetUserProfile(ctx context.Context, userID int64) (*UserProfile, error)
	UpsertUserProfile(ctx context.Context, profile UserProfile) (*UserProfile, error)
	CreateSession(ctx context.Context, params CreateSessionParams) (*Session, error)
	GetSessionByTokenHash(ctx context.Context, tokenHash string) (*Session, error)
	RotateSessionToken(ctx context.Context, sessionID int64, tokenHash string, expiresAt time.Time, lastUsedAt time.Time) (*Session, error)
	RevokeSessionByTokenHash(ctx context.Context, tokenHash string, revokedAt time.Time) error
	RevokeAllUserSessions(ctx context.Context, userID int64, revokedAt time.Time) error
	CreateOneTimeToken(ctx context.Context, params CreateOneTimeTokenParams) (*OneTimeToken, error)
	GetValidOneTimeToken(ctx context.Context, purpose, tokenHash string) (*OneTimeToken, error)
	ConsumeOneTimeToken(ctx context.Context, tokenID int64, consumedAt time.Time) error
	ReplaceOneTimeToken(ctx context.Context, params CreateOneTimeTokenParams) (*OneTimeToken, error)
	MarkUserEmailVerified(ctx context.Context, userID int64, verifiedAt time.Time) error
	UpdatePasswordHash(ctx context.Context, userID int64, passwordHash string) error
	GetOAuthAccount(ctx context.Context, provider OAuthProvider, providerUserID string) (*OAuthAccount, error)
	CreateOAuthAccount(ctx context.Context, params CreateOAuthAccountParams) (*OAuthAccount, error)
	UpdateUserRole(ctx context.Context, userID int64, role Role) error
	UpdateAccountStatus(ctx context.Context, userID int64, status AccountStatus) error
	CreateAuditLog(ctx context.Context, params CreateAuditLogParams) error
}

type PostgresRepository struct {
	db *sqlx.DB
}

func NewRepository(db *sqlx.DB) *PostgresRepository {
	return &PostgresRepository{db: db}
}

func scanUser(scanner interface{ Scan(dest ...any) error }, user *User) error {
	return scanner.Scan(
		&user.ID,
		&user.Email,
		&user.Username,
		&user.PasswordHash,
		&user.EmailVerifiedAt,
		&user.Role,
		&user.AccountStatus,
		&user.CreatedAt,
	)
}

func (r *PostgresRepository) CreateUser(ctx context.Context, params CreateUserParams) (*User, error) {
	user := &User{}

	role := params.Role
	if role == "" {
		role = RoleUser
	}
	status := params.AccountStatus
	if status == "" {
		status = AccountStatusActive
	}

	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin create user transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	const userQuery = `
		INSERT INTO users (email, username, password_hash, email_verified_at, account_status, role_id)
		VALUES ($1, $2, $3, $4, $5, (SELECT id FROM roles WHERE name = $6))
		RETURNING id, email, username, password_hash, email_verified_at, account_status, created_at;
	`
	if err := tx.QueryRowContext(ctx, userQuery, params.Email, params.Username, params.PasswordHash, params.EmailVerifiedAt, status, role).Scan(
		&user.ID,
		&user.Email,
		&user.Username,
		&user.PasswordHash,
		&user.EmailVerifiedAt,
		&user.AccountStatus,
		&user.CreatedAt,
	); err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			return nil, ErrUserAlreadyExists
		}
		return nil, fmt.Errorf("create user: %w", err)
	}
	user.Role = role

	const profileQuery = `
		INSERT INTO user_profiles (user_id, full_name, avatar_url, status, timezone)
		VALUES ($1, '', '', '', 'UTC');
	`
	if _, err := tx.ExecContext(ctx, profileQuery, user.ID); err != nil {
		return nil, fmt.Errorf("create user profile: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit create user transaction: %w", err)
	}

	return user, nil
}

func (r *PostgresRepository) GetUserByID(ctx context.Context, id int64) (*User, error) {
	const query = `
		SELECT u.id, u.email, u.username, u.password_hash, u.email_verified_at, r.name, u.account_status, u.created_at
		FROM users u
		JOIN roles r ON r.id = u.role_id
		WHERE u.id = $1;
	`
	user := &User{}
	if err := scanUser(r.db.QueryRowContext(ctx, query, id), user); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUnauthorized
		}
		return nil, fmt.Errorf("get user by id: %w", err)
	}
	return user, nil
}

func (r *PostgresRepository) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	const query = `
		SELECT u.id, u.email, u.username, u.password_hash, u.email_verified_at, r.name, u.account_status, u.created_at
		FROM users u
		JOIN roles r ON r.id = u.role_id
		WHERE u.username = $1;
	`
	return r.getUser(ctx, query, username)
}

func (r *PostgresRepository) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	const query = `
		SELECT u.id, u.email, u.username, u.password_hash, u.email_verified_at, r.name, u.account_status, u.created_at
		FROM users u
		JOIN roles r ON r.id = u.role_id
		WHERE u.email = $1;
	`
	return r.getUser(ctx, query, email)
}

func (r *PostgresRepository) getUser(ctx context.Context, query string, arg any) (*User, error) {
	user := &User{}
	if err := scanUser(r.db.QueryRowContext(ctx, query, arg), user); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("get user: %w", err)
	}
	return user, nil
}

func (r *PostgresRepository) GetUserProfile(ctx context.Context, userID int64) (*UserProfile, error) {
	profile := &UserProfile{}

	const query = `
		SELECT user_id, full_name, avatar_url, status, timezone, updated_at
		FROM user_profiles
		WHERE user_id = $1;
	`
	err := r.db.QueryRowContext(ctx, query, userID).Scan(
		&profile.UserID,
		&profile.FullName,
		&profile.AvatarURL,
		&profile.Status,
		&profile.Timezone,
		&profile.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUnauthorized
		}
		return nil, fmt.Errorf("get user profile: %w", err)
	}

	return profile, nil
}

func (r *PostgresRepository) UpsertUserProfile(ctx context.Context, profile UserProfile) (*UserProfile, error) {
	result := &UserProfile{}

	const query = `
		INSERT INTO user_profiles (user_id, full_name, avatar_url, status, timezone, updated_at)
		VALUES ($1, $2, $3, $4, $5, NOW())
		ON CONFLICT (user_id)
		DO UPDATE SET
			full_name = EXCLUDED.full_name,
			avatar_url = EXCLUDED.avatar_url,
			status = EXCLUDED.status,
			timezone = EXCLUDED.timezone,
			updated_at = NOW()
		RETURNING user_id, full_name, avatar_url, status, timezone, updated_at;
	`
	err := r.db.QueryRowContext(ctx, query, profile.UserID, profile.FullName, profile.AvatarURL, profile.Status, profile.Timezone).Scan(
		&result.UserID,
		&result.FullName,
		&result.AvatarURL,
		&result.Status,
		&result.Timezone,
		&result.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("upsert user profile: %w", err)
	}

	return result, nil
}

func (r *PostgresRepository) CreateSession(ctx context.Context, params CreateSessionParams) (*Session, error) {
	session := &Session{}
	const query = `
		INSERT INTO sessions (user_id, token_hash, expires_at)
		VALUES ($1, $2, $3)
		RETURNING id, user_id, token_hash, expires_at, revoked_at, last_used_at, created_at;
	`
	err := r.db.QueryRowContext(ctx, query, params.UserID, params.TokenHash, params.ExpiresAt).Scan(
		&session.ID, &session.UserID, &session.TokenHash, &session.ExpiresAt,
		&session.RevokedAt, &session.LastUsedAt, &session.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}
	return session, nil
}

func (r *PostgresRepository) GetSessionByTokenHash(ctx context.Context, tokenHash string) (*Session, error) {
	session := &Session{}
	const query = `
		SELECT id, user_id, token_hash, expires_at, revoked_at, last_used_at, created_at
		FROM sessions
		WHERE token_hash = $1;
	`
	err := r.db.QueryRowContext(ctx, query, tokenHash).Scan(
		&session.ID, &session.UserID, &session.TokenHash, &session.ExpiresAt,
		&session.RevokedAt, &session.LastUsedAt, &session.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrInvalidToken
		}
		return nil, fmt.Errorf("get session: %w", err)
	}
	return session, nil
}

func (r *PostgresRepository) RotateSessionToken(ctx context.Context, sessionID int64, tokenHash string, expiresAt, lastUsedAt time.Time) (*Session, error) {
	session := &Session{}
	const query = `
		UPDATE sessions
		SET token_hash = $2, expires_at = $3, last_used_at = $4, revoked_at = NULL
		WHERE id = $1
		RETURNING id, user_id, token_hash, expires_at, revoked_at, last_used_at, created_at;
	`
	err := r.db.QueryRowContext(ctx, query, sessionID, tokenHash, expiresAt, lastUsedAt).Scan(
		&session.ID, &session.UserID, &session.TokenHash, &session.ExpiresAt,
		&session.RevokedAt, &session.LastUsedAt, &session.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrInvalidToken
		}
		return nil, fmt.Errorf("rotate session: %w", err)
	}
	return session, nil
}

func (r *PostgresRepository) RevokeSessionByTokenHash(ctx context.Context, tokenHash string, revokedAt time.Time) error {
	const query = `
		UPDATE sessions
		SET revoked_at = $2
		WHERE token_hash = $1 AND revoked_at IS NULL;
	`
	_, err := r.db.ExecContext(ctx, query, tokenHash, revokedAt)
	if err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	return nil
}

func (r *PostgresRepository) RevokeAllUserSessions(ctx context.Context, userID int64, revokedAt time.Time) error {
	const query = `
		UPDATE sessions
		SET revoked_at = $2
		WHERE user_id = $1 AND revoked_at IS NULL;
	`
	_, err := r.db.ExecContext(ctx, query, userID, revokedAt)
	if err != nil {
		return fmt.Errorf("revoke all sessions: %w", err)
	}
	return nil
}

func (r *PostgresRepository) CreateOneTimeToken(ctx context.Context, params CreateOneTimeTokenParams) (*OneTimeToken, error) {
	token := &OneTimeToken{}
	const query = `
		INSERT INTO one_time_tokens (user_id, purpose, token_hash, expires_at)
		VALUES ($1, $2, $3, $4)
		RETURNING id, user_id, purpose, token_hash, expires_at, consumed_at, created_at;
	`
	err := r.db.QueryRowContext(ctx, query, params.UserID, params.Purpose, params.TokenHash, params.ExpiresAt).Scan(
		&token.ID, &token.UserID, &token.Purpose, &token.TokenHash, &token.ExpiresAt, &token.ConsumedAt, &token.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("create one-time token: %w", err)
	}
	return token, nil
}

func (r *PostgresRepository) ReplaceOneTimeToken(ctx context.Context, params CreateOneTimeTokenParams) (*OneTimeToken, error) {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin replace one-time token transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	const revokeQuery = `
		UPDATE one_time_tokens
		SET consumed_at = NOW()
		WHERE user_id = $1 AND purpose = $2 AND consumed_at IS NULL;
	`
	if _, err := tx.ExecContext(ctx, revokeQuery, params.UserID, params.Purpose); err != nil {
		return nil, fmt.Errorf("revoke old one-time tokens: %w", err)
	}

	token := &OneTimeToken{}
	const query = `
		INSERT INTO one_time_tokens (user_id, purpose, token_hash, expires_at)
		VALUES ($1, $2, $3, $4)
		RETURNING id, user_id, purpose, token_hash, expires_at, consumed_at, created_at;
	`
	err = tx.QueryRowContext(ctx, query, params.UserID, params.Purpose, params.TokenHash, params.ExpiresAt).Scan(
		&token.ID, &token.UserID, &token.Purpose, &token.TokenHash, &token.ExpiresAt, &token.ConsumedAt, &token.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("insert one-time token: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit replace one-time token transaction: %w", err)
	}
	return token, nil
}

func (r *PostgresRepository) GetValidOneTimeToken(ctx context.Context, purpose, tokenHash string) (*OneTimeToken, error) {
	token := &OneTimeToken{}
	const query = `
		SELECT id, user_id, purpose, token_hash, expires_at, consumed_at, created_at
		FROM one_time_tokens
		WHERE purpose = $1 AND token_hash = $2;
	`
	err := r.db.QueryRowContext(ctx, query, purpose, tokenHash).Scan(
		&token.ID, &token.UserID, &token.Purpose, &token.TokenHash, &token.ExpiresAt, &token.ConsumedAt, &token.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrInvalidToken
		}
		return nil, fmt.Errorf("get one-time token: %w", err)
	}
	return token, nil
}

func (r *PostgresRepository) ConsumeOneTimeToken(ctx context.Context, tokenID int64, consumedAt time.Time) error {
	const query = `
		UPDATE one_time_tokens
		SET consumed_at = $2
		WHERE id = $1 AND consumed_at IS NULL;
	`
	result, err := r.db.ExecContext(ctx, query, tokenID, consumedAt)
	if err != nil {
		return fmt.Errorf("consume one-time token: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("consume one-time token rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return ErrInvalidToken
	}
	return nil
}

func (r *PostgresRepository) MarkUserEmailVerified(ctx context.Context, userID int64, verifiedAt time.Time) error {
	const query = `
		UPDATE users
		SET email_verified_at = COALESCE(email_verified_at, $2)
		WHERE id = $1;
	`
	_, err := r.db.ExecContext(ctx, query, userID, verifiedAt)
	if err != nil {
		return fmt.Errorf("mark user verified: %w", err)
	}
	return nil
}

func (r *PostgresRepository) UpdatePasswordHash(ctx context.Context, userID int64, passwordHash string) error {
	const query = `
		UPDATE users
		SET password_hash = $2
		WHERE id = $1;
	`
	_, err := r.db.ExecContext(ctx, query, userID, passwordHash)
	if err != nil {
		return fmt.Errorf("update password hash: %w", err)
	}
	return nil
}

func (r *PostgresRepository) GetOAuthAccount(ctx context.Context, provider OAuthProvider, providerUserID string) (*OAuthAccount, error) {
	account := &OAuthAccount{}
	const query = `
		SELECT id, user_id, provider, provider_user_id, created_at
		FROM oauth_accounts
		WHERE provider = $1 AND provider_user_id = $2;
	`
	err := r.db.QueryRowContext(ctx, query, provider, providerUserID).Scan(
		&account.ID, &account.UserID, &account.Provider, &account.ProviderUserID, &account.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUnauthorized
		}
		return nil, fmt.Errorf("get oauth account: %w", err)
	}
	return account, nil
}

func (r *PostgresRepository) CreateOAuthAccount(ctx context.Context, params CreateOAuthAccountParams) (*OAuthAccount, error) {
	account := &OAuthAccount{}
	const query = `
		INSERT INTO oauth_accounts (user_id, provider, provider_user_id)
		VALUES ($1, $2, $3)
		RETURNING id, user_id, provider, provider_user_id, created_at;
	`
	err := r.db.QueryRowContext(ctx, query, params.UserID, params.Provider, params.ProviderUserID).Scan(
		&account.ID, &account.UserID, &account.Provider, &account.ProviderUserID, &account.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("create oauth account: %w", err)
	}
	return account, nil
}

func (r *PostgresRepository) UpdateUserRole(ctx context.Context, userID int64, role Role) error {
	const query = `
		UPDATE users AS u
		SET role_id = r.id
		FROM roles AS r
		WHERE u.id = $1
		  AND r.name = $2;
	`
	_, err := r.db.ExecContext(ctx, query, userID, role)
	if err != nil {
		return fmt.Errorf("update user role: %w", err)
	}
	return nil
}

func (r *PostgresRepository) UpdateAccountStatus(ctx context.Context, userID int64, status AccountStatus) error {
	const query = `
		UPDATE users
		SET account_status = $2
		WHERE id = $1;
	`
	_, err := r.db.ExecContext(ctx, query, userID, status)
	if err != nil {
		return fmt.Errorf("update account status: %w", err)
	}
	return nil
}

func (r *PostgresRepository) CreateAuditLog(ctx context.Context, params CreateAuditLogParams) error {
	details := params.Details
	if details == nil {
		details = map[string]any{}
	}
	payload, err := json.Marshal(details)
	if err != nil {
		return fmt.Errorf("marshal audit details: %w", err)
	}
	const query = `
		INSERT INTO audit_logs (user_id, actor_user_id, action, details)
		VALUES ($1, $2, $3, $4::jsonb)
	`
	_, err = r.db.ExecContext(ctx, query, params.UserID, params.ActorUserID, params.Action, string(payload))
	if err != nil {
		return fmt.Errorf("create audit log: %w", err)
	}
	return nil
}
