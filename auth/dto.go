package auth

import "time"

type RegisterRequest struct {
	Username string `json:"username,omitempty"`
	Email    string `json:"email,omitempty"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Username string `json:"username,omitempty"`
	Email    string `json:"email,omitempty"`
	Password string `json:"password"`
}

type TokenResponse struct {
	AccessToken           string    `json:"access_token"`
	AccessTokenExpiresAt  time.Time `json:"access_token_expires_at"`
	RefreshToken          string    `json:"refresh_token"`
	RefreshTokenExpiresAt time.Time `json:"refresh_token_expires_at"`
}

type RegisterResponse struct {
	Status string `json:"status"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type LogoutRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type VerifyEmailRequest struct {
	Token string `json:"token"`
}

type RequestEmailVerificationRequest struct {
	Email string `json:"email"`
}

type RequestPasswordResetRequest struct {
	Email string `json:"email"`
}

type ResetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

type OneTimeTokenResponse struct {
	Status string `json:"status"`
}

type UpdateProfileRequest struct {
	FullName  string `json:"full_name"`
	AvatarURL string `json:"avatar_url"`
	Status    string `json:"status"`
	Timezone  string `json:"timezone"`
}

type UpdateUserRoleRequest struct {
	Role Role `json:"role"`
}

type UpdateUserStatusRequest struct {
	Status AccountStatus `json:"status"`
}

type OAuthStartResponse struct {
	Provider         OAuthProvider `json:"provider"`
	AuthorizationURL string        `json:"authorization_url"`
	State            string        `json:"state"`
}

type OAuthCallbackResponse struct {
	User   *UserProfileResponse `json:"user"`
	Tokens *TokenResponse       `json:"tokens"`
}

type UserProfileResponse struct {
	ID              int64         `json:"id"`
	Username        string        `json:"username"`
	Email           string        `json:"email"`
	EmailVerifiedAt *time.Time    `json:"email_verified_at,omitempty"`
	Role            Role          `json:"role"`
	AccountStatus   AccountStatus `json:"account_status"`
	Profile         UserProfile   `json:"profile"`
}
