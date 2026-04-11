package auth

import "time"

type Role string

const (
	RoleUser      Role = "user"
	RoleModerator Role = "moderator"
	RoleAdmin     Role = "admin"
)

type AccountStatus string

const (
	AccountStatusActive      AccountStatus = "active"
	AccountStatusBlocked     AccountStatus = "blocked"
	AccountStatusDeactivated AccountStatus = "deactivated"
)

type User struct {
	ID              int64
	Username        string
	Email           string
	PasswordHash    string
	EmailVerifiedAt *time.Time
	Role            Role
	AccountStatus   AccountStatus
	CreatedAt       time.Time
}

type UserProfile struct {
	UserID    int64     `json:"user_id"`
	FullName  string    `json:"full_name"`
	AvatarURL string    `json:"avatar_url"`
	Status    string    `json:"status"`
	Timezone  string    `json:"timezone"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Session struct {
	ID         int64
	UserID     int64
	TokenHash  string
	ExpiresAt  time.Time
	RevokedAt  *time.Time
	LastUsedAt *time.Time
	CreatedAt  time.Time
}

type OneTimeToken struct {
	ID         int64
	UserID     int64
	Purpose    string
	TokenHash  string
	ExpiresAt  time.Time
	ConsumedAt *time.Time
	CreatedAt  time.Time
}

type OAuthProvider string

const (
	OAuthProviderGoogle OAuthProvider = "google"
	OAuthProviderGitHub OAuthProvider = "github"
	OAuthProviderVK     OAuthProvider = "vk"
)

type OAuthIdentity struct {
	Provider       OAuthProvider
	ProviderUserID string
	Email          string
	Username       string
	FullName       string
	AvatarURL      string
	EmailVerified  bool
}

type OAuthAccount struct {
	ID             int64
	UserID         int64
	Provider       OAuthProvider
	ProviderUserID string
	CreatedAt      time.Time
}

type AuditAction string

const (
	AuditActionLoginSucceeded       AuditAction = "login_succeeded"
	AuditActionTokenIssued          AuditAction = "token_issued"
	AuditActionPasswordChanged      AuditAction = "password_changed"
	AuditActionAccountBlocked       AuditAction = "account_blocked"
	AuditActionAccountDeactivated   AuditAction = "account_deactivated"
	AuditActionAccountStatusChanged AuditAction = "account_status_changed"
	AuditActionRoleChanged          AuditAction = "role_changed"
	AuditActionOAuthLogin           AuditAction = "oauth_login"
)

type AuditLog struct {
	ID          int64
	UserID      *int64
	ActorUserID *int64
	Action      AuditAction
	Details     string
	CreatedAt   time.Time
}
