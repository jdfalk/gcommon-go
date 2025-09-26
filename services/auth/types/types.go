// file: services/auth/types/types.go
// version: 1.0.0
// guid: k6l7m8n9-o0p1-q2r3-s4t5-u6v7w8x9y0z1

package types

import "context"

// LoginRequest represents a user login request
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse represents a login response with tokens
type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

// ValidateTokenRequest represents a token validation request
type ValidateTokenRequest struct {
	Token string `json:"token"`
}

// ValidateTokenResponse represents a token validation response
type ValidateTokenResponse struct {
	Valid  bool     `json:"valid"`
	UserId string   `json:"user_id"`
	Roles  []string `json:"roles"`
}

// AuthorizeRequest represents an authorization request
type AuthorizeRequest struct {
	Token        string   `json:"token"`
	RequiredRole string   `json:"required_role"`
	Resource     string   `json:"resource"`
	Action       string   `json:"action"`
	Permissions  []string `json:"permissions"`
}

// AuthorizeResponse represents an authorization response
type AuthorizeResponse struct {
	Authorized bool     `json:"authorized"`
	Reason     string   `json:"reason"`
	Roles      []string `json:"roles"`
}

// GenerateTokenRequest represents a token generation request
type GenerateTokenRequest struct {
	UserId      string   `json:"user_id"`
	Roles       []string `json:"roles"`
	ExpiresIn   int64    `json:"expires_in"`
	TokenType   string   `json:"token_type"`
	Permissions []string `json:"permissions"`
}

// GenerateTokenResponse represents a token generation response
type GenerateTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

// RefreshTokenRequest represents a token refresh request
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// RefreshTokenResponse represents a token refresh response
type RefreshTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

// RevokeTokenRequest represents a token revocation request
type RevokeTokenRequest struct {
	Token     string `json:"token"`
	TokenType string `json:"token_type"`
}

// RevokeTokenResponse represents a token revocation response
type RevokeTokenResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// AuthService defines the authentication service interface
type AuthService interface {
	ValidateToken(ctx context.Context, req *ValidateTokenRequest) (*ValidateTokenResponse, error)
	AuthorizeAccess(ctx context.Context, req *AuthorizeRequest) (*AuthorizeResponse, error)
	GenerateToken(ctx context.Context, req *GenerateTokenRequest) (*GenerateTokenResponse, error)
	RefreshToken(ctx context.Context, req *RefreshTokenRequest) (*RefreshTokenResponse, error)
	RevokeToken(ctx context.Context, req *RevokeTokenRequest) (*RevokeTokenResponse, error)
}

// Role represents user roles
type Role string

const (
	RoleAdmin Role = "admin"
	RoleUser  Role = "user"
	RoleGuest Role = "guest"
)
