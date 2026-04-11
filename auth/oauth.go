package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type OAuthProviderClient interface {
	AuthCodeURL(state string) string
	Exchange(ctx context.Context, code string) (*OAuthIdentity, error)
}

type oauthHTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type googleOAuthClient struct {
	client       oauthHTTPClient
	clientID     string
	clientSecret string
	redirectURL  string
}

func NewGoogleOAuthClient(client oauthHTTPClient, clientID, clientSecret, redirectURL string) OAuthProviderClient {
	return &googleOAuthClient{
		client:       client,
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURL:  redirectURL,
	}
}

func (c *googleOAuthClient) AuthCodeURL(state string) string {
	values := url.Values{}
	values.Set("client_id", c.clientID)
	values.Set("redirect_uri", c.redirectURL)
	values.Set("response_type", "code")
	values.Set("scope", "openid email profile")
	values.Set("access_type", "offline")
	values.Set("state", state)
	return "https://accounts.google.com/o/oauth2/v2/auth?" + values.Encode()
}

func (c *googleOAuthClient) Exchange(ctx context.Context, code string) (*OAuthIdentity, error) {
	form := url.Values{}
	form.Set("client_id", c.clientID)
	form.Set("client_secret", c.clientSecret)
	form.Set("code", code)
	form.Set("grant_type", "authorization_code")
	form.Set("redirect_uri", c.redirectURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://oauth2.googleapis.com/token", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build google token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := doJSON(c.client, req, &tokenResp); err != nil {
		return nil, fmt.Errorf("exchange google code: %w", err)
	}

	userReq, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://openidconnect.googleapis.com/v1/userinfo", nil)
	if err != nil {
		return nil, fmt.Errorf("build google userinfo request: %w", err)
	}
	userReq.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)

	var userInfo struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
		Picture       string `json:"picture"`
	}
	if err := doJSON(c.client, userReq, &userInfo); err != nil {
		return nil, fmt.Errorf("fetch google userinfo: %w", err)
	}

	return &OAuthIdentity{
		Provider:       OAuthProviderGoogle,
		ProviderUserID: userInfo.Sub,
		Email:          strings.ToLower(strings.TrimSpace(userInfo.Email)),
		Username:       usernameFromEmail(userInfo.Email),
		FullName:       userInfo.Name,
		AvatarURL:      userInfo.Picture,
		EmailVerified:  userInfo.EmailVerified,
	}, nil
}

type gitHubOAuthClient struct {
	client       oauthHTTPClient
	clientID     string
	clientSecret string
	redirectURL  string
}

func NewGitHubOAuthClient(client oauthHTTPClient, clientID, clientSecret, redirectURL string) OAuthProviderClient {
	return &gitHubOAuthClient{
		client:       client,
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURL:  redirectURL,
	}
}

func (c *gitHubOAuthClient) AuthCodeURL(state string) string {
	values := url.Values{}
	values.Set("client_id", c.clientID)
	values.Set("redirect_uri", c.redirectURL)
	values.Set("scope", "read:user user:email")
	values.Set("state", state)
	return "https://github.com/login/oauth/authorize?" + values.Encode()
}

func (c *gitHubOAuthClient) Exchange(ctx context.Context, code string) (*OAuthIdentity, error) {
	form := url.Values{}
	form.Set("client_id", c.clientID)
	form.Set("client_secret", c.clientSecret)
	form.Set("code", code)
	form.Set("redirect_uri", c.redirectURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://github.com/login/oauth/access_token", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build github token request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := doJSON(c.client, req, &tokenResp); err != nil {
		return nil, fmt.Errorf("exchange github code: %w", err)
	}

	userReq, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user", nil)
	if err != nil {
		return nil, fmt.Errorf("build github user request: %w", err)
	}
	userReq.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	userReq.Header.Set("Accept", "application/vnd.github+json")

	var userInfo struct {
		ID        int64  `json:"id"`
		Login     string `json:"login"`
		Name      string `json:"name"`
		AvatarURL string `json:"avatar_url"`
		Email     string `json:"email"`
	}
	if err := doJSON(c.client, userReq, &userInfo); err != nil {
		return nil, fmt.Errorf("fetch github user: %w", err)
	}

	email := strings.ToLower(strings.TrimSpace(userInfo.Email))
	verified := email != ""
	if email == "" {
		emailReq, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user/emails", nil)
		if err != nil {
			return nil, fmt.Errorf("build github emails request: %w", err)
		}
		emailReq.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
		emailReq.Header.Set("Accept", "application/vnd.github+json")

		var emails []struct {
			Email    string `json:"email"`
			Primary  bool   `json:"primary"`
			Verified bool   `json:"verified"`
		}
		if err := doJSON(c.client, emailReq, &emails); err != nil {
			return nil, fmt.Errorf("fetch github emails: %w", err)
		}
		for _, candidate := range emails {
			if candidate.Primary {
				email = strings.ToLower(strings.TrimSpace(candidate.Email))
				verified = candidate.Verified
				break
			}
		}
	}

	return &OAuthIdentity{
		Provider:       OAuthProviderGitHub,
		ProviderUserID: fmt.Sprintf("%d", userInfo.ID),
		Email:          email,
		Username:       strings.TrimSpace(userInfo.Login),
		FullName:       userInfo.Name,
		AvatarURL:      userInfo.AvatarURL,
		EmailVerified:  verified,
	}, nil
}

func doJSON(client oauthHTTPClient, req *http.Request, target any) error {
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected status: %s", resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(target); err != nil {
		return fmt.Errorf("decode json response: %w", err)
	}
	return nil
}

func usernameFromEmail(email string) string {
	prefix, _, _ := strings.Cut(strings.ToLower(strings.TrimSpace(email)), "@")
	return prefix
}

type vkOAuthClient struct {
	client       oauthHTTPClient
	clientID     string
	clientSecret string
	redirectURL  string
}

func NewVKOAuthClient(client oauthHTTPClient, clientID, clientSecret, redirectURL string) OAuthProviderClient {
	return &vkOAuthClient{
		client:       client,
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURL:  redirectURL,
	}
}

func (c *vkOAuthClient) AuthCodeURL(state string) string {
	values := url.Values{}
	values.Set("client_id", c.clientID)
	values.Set("redirect_uri", c.redirectURL)
	values.Set("response_type", "code")
	values.Set("scope", "email")
	values.Set("state", state)
	return "https://oauth.vk.com/authorize?" + values.Encode()
}

func (c *vkOAuthClient) Exchange(ctx context.Context, code string) (*OAuthIdentity, error) {
	form := url.Values{}
	form.Set("client_id", c.clientID)
	form.Set("client_secret", c.clientSecret)
	form.Set("code", code)
	form.Set("redirect_uri", c.redirectURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://oauth.vk.com/access_token", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build vk token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		UserID      int64  `json:"user_id"`
		Email       string `json:"email"`
	}
	if err := doJSON(c.client, req, &tokenResp); err != nil {
		return nil, fmt.Errorf("exchange vk code: %w", err)
	}

	userInfoURL := fmt.Sprintf(
		"https://api.vk.com/method/users.get?user_ids=%d&fields=photo_200,screen_name&access_token=%s&v=5.199",
		tokenResp.UserID,
		url.QueryEscape(tokenResp.AccessToken),
	)
	userReq, err := http.NewRequestWithContext(ctx, http.MethodGet, userInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build vk user request: %w", err)
	}

	var userResp struct {
		Response []struct {
			ID         int64  `json:"id"`
			FirstName  string `json:"first_name"`
			LastName   string `json:"last_name"`
			Photo200   string `json:"photo_200"`
			ScreenName string `json:"screen_name"`
		} `json:"response"`
	}
	if err := doJSON(c.client, userReq, &userResp); err != nil {
		return nil, fmt.Errorf("fetch vk user: %w", err)
	}
	if len(userResp.Response) == 0 {
		return nil, fmt.Errorf("fetch vk user: empty response")
	}

	userInfo := userResp.Response[0]
	fullName := strings.TrimSpace(strings.TrimSpace(userInfo.FirstName + " " + userInfo.LastName))
	email := strings.ToLower(strings.TrimSpace(tokenResp.Email))

	return &OAuthIdentity{
		Provider:       OAuthProviderVK,
		ProviderUserID: fmt.Sprintf("%d", userInfo.ID),
		Email:          email,
		Username:       strings.TrimSpace(userInfo.ScreenName),
		FullName:       fullName,
		AvatarURL:      userInfo.Photo200,
		EmailVerified:  email != "",
	}, nil
}
