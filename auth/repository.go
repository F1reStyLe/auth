package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

const (
	tokenPurposeVerifyEmail   = "verify_email"
	tokenPurposeResetPassword = "reset_password"
)

type CreateUserParams struct {
	Email        string
	Username     string
	PasswordHash string
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

type Repository interface {
	CreateUser(ctx context.Context, params CreateUserParams) (*User, error)
	GetUserByID(ctx context.Context, id int64) (*User, error)
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
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
}

type PostgresRepository struct {
	db *sqlx.DB
}

func NewRepository(db *sqlx.DB) *PostgresRepository {
	return &PostgresRepository{db: db}
}

func (r *PostgresRepository) CreateUser(ctx context.Context, params CreateUserParams) (*User, error) {
	user := &User{}

	const query = `
		INSERT INTO users (email, username, password_hash)
		VALUES ($1, $2, $3)
		RETURNING id, email, username, password_hash, email_verified_at, created_at;
	`

	err := r.db.QueryRowContext(ctx, query, params.Email, params.Username, params.PasswordHash).Scan(
		&user.ID, &user.Email, &user.Username, &user.PasswordHash, &user.EmailVerifiedAt, &user.CreatedAt,
	)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			return nil, ErrUserAlreadyExists
		}
		return nil, fmt.Errorf("create user: %w", err)
	}

	return user, nil
}

func (r *PostgresRepository) GetUserByID(ctx context.Context, id int64) (*User, error) {
	user := &User{}

	const query = `
		SELECT id, email, username, password_hash, email_verified_at, created_at
		FROM users
		WHERE id = $1;
	`

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&user.ID, &user.Email, &user.Username, &user.PasswordHash, &user.EmailVerifiedAt, &user.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUnauthorized
		}
		return nil, fmt.Errorf("get user by id: %w", err)
	}

	return user, nil
}

func (r *PostgresRepository) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	user := &User{}

	const query = `
		SELECT id, email, username, password_hash, email_verified_at, created_at
		FROM users
		WHERE username = $1;
	`

	err := r.db.QueryRowContext(ctx, query, username).Scan(
		&user.ID, &user.Email, &user.Username, &user.PasswordHash, &user.EmailVerifiedAt, &user.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("get user by username: %w", err)
	}

	return user, nil
}

func (r *PostgresRepository) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	user := &User{}

	const query = `
		SELECT id, email, username, password_hash, email_verified_at, created_at
		FROM users
		WHERE email = $1;
	`

	err := r.db.QueryRowContext(ctx, query, email).Scan(
		&user.ID, &user.Email, &user.Username, &user.PasswordHash, &user.EmailVerifiedAt, &user.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("get user by email: %w", err)
	}

	return user, nil
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

func (r *PostgresRepository) RotateSessionToken(ctx context.Context, sessionID int64, tokenHash string, expiresAt time.Time, lastUsedAt time.Time) (*Session, error) {
	session := &Session{}

	const query = `
		UPDATE sessions
		SET token_hash = $2,
			expires_at = $3,
			last_used_at = $4,
			revoked_at = NULL
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

	if _, err := r.db.ExecContext(ctx, query, tokenHash, revokedAt); err != nil {
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

	if _, err := r.db.ExecContext(ctx, query, userID, revokedAt); err != nil {
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
	defer func() {
		_ = tx.Rollback()
	}()

	const revokeQuery = `
		UPDATE one_time_tokens
		SET consumed_at = NOW()
		WHERE user_id = $1 AND purpose = $2 AND consumed_at IS NULL;
	`
	if _, err := tx.ExecContext(ctx, revokeQuery, params.UserID, params.Purpose); err != nil {
		return nil, fmt.Errorf("revoke old one-time tokens: %w", err)
	}

	token := &OneTimeToken{}
	const insertQuery = `
		INSERT INTO one_time_tokens (user_id, purpose, token_hash, expires_at)
		VALUES ($1, $2, $3, $4)
		RETURNING id, user_id, purpose, token_hash, expires_at, consumed_at, created_at;
	`

	err = tx.QueryRowContext(ctx, insertQuery, params.UserID, params.Purpose, params.TokenHash, params.ExpiresAt).Scan(
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

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("consume one-time token rows affected: %w", err)
	}
	if affected == 0 {
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

	if _, err := r.db.ExecContext(ctx, query, userID, verifiedAt); err != nil {
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

	if _, err := r.db.ExecContext(ctx, query, userID, passwordHash); err != nil {
		return fmt.Errorf("update password hash: %w", err)
	}

	return nil
}
