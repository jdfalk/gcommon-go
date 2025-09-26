// file: services/auth/service.go
// version: 1.0.0
// guid: n4o5p6q7-r8s9-0123-7890-234567890123

package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jdfalk/gcommon/pkg/authpb"
	"github.com/jdfalk/gcommon/services/auth/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// AuthenticationService implements the auth service with hybrid architecture
type AuthenticationService struct {
	authpb.UnimplementedAuthServiceServer
	jwtSecret    []byte
	rsaPrivKey   *rsa.PrivateKey
	rsaPubKey    *rsa.PublicKey
	tokenExpiry  time.Duration
	refreshExpiry time.Duration
	users        map[string]types.User // In-memory user store for demo
}

// User represents a user in our system
type User struct {
	ID       string
	Username string
	Password string // In production, this should be hashed
	Roles    []string
}

// NewAuthService creates a new authentication service
func NewAuthService(jwtSecret []byte) (*AuthenticationService, error) {
	// Generate RSA key pair for JWT signing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	service := &AuthenticationService{
		jwtSecret:     jwtSecret,
		rsaPrivKey:    privateKey,
		rsaPubKey:     &privateKey.PublicKey,
		tokenExpiry:   time.Hour,
		refreshExpiry: time.Hour * 24 * 7, // 7 days
		users:         make(map[string]types.User),
	}

	// Add demo users
	service.users["admin"] = types.User{
		ID:       "1",
		Username: "admin",
		Password: "admin123", // In production, use proper hashing
		Roles:    []string{"admin", "user"},
	}
	service.users["user"] = types.User{
		ID:       "2",
		Username: "user",
		Password: "user123",
		Roles:    []string{"user"},
	}

	return service, nil
}

// Login authenticates a user and returns JWT tokens
func (s *AuthenticationService) Login(ctx context.Context, req *authpb.LoginRequest) (*authpb.LoginResponse, error) {
	// Convert protobuf request to internal type
	internalReq := &types.LoginRequest{
		Username: req.GetUsername(),
		Password: req.GetPassword(),
	}

	// Validate credentials
	user, exists := s.users[internalReq.Username]
	if !exists || user.Password != internalReq.Password {
		return nil, status.Errorf(codes.Unauthenticated, "invalid credentials")
	}

	// Generate tokens
	accessToken, err := s.generateToken(user.ID, user.Roles, s.tokenExpiry, "access")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate access token: %v", err)
	}

	refreshToken, err := s.generateToken(user.ID, user.Roles, s.refreshExpiry, "refresh")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate refresh token: %v", err)
	}

	// Convert internal response to protobuf
	return &authpb.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(s.tokenExpiry.Seconds()),
	}, nil
}

// ValidateToken validates a JWT token and returns user claims
func (s *AuthenticationService) ValidateToken(ctx context.Context, req *authpb.ValidateTokenRequest) (*authpb.ValidateTokenResponse, error) {
	// Convert protobuf to internal type
	internalReq := &types.ValidateTokenRequest{
		Token: req.GetToken(),
	}

	// Parse and validate token
	token, err := jwt.Parse(internalReq.Token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.rsaPubKey, nil
	})

	if err != nil || !token.Valid {
		return &authpb.ValidateTokenResponse{
			Valid:  false,
			UserId: "",
			Roles:  []string{},
		}, nil
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return &authpb.ValidateTokenResponse{
			Valid:  false,
			UserId: "",
			Roles:  []string{},
		}, nil
	}

	userId, _ := claims["user_id"].(string)
	rolesInterface, _ := claims["roles"].([]interface{})
	roles := make([]string, len(rolesInterface))
	for i, role := range rolesInterface {
		roles[i] = role.(string)
	}

	return &authpb.ValidateTokenResponse{
		Valid:  true,
		UserId: userId,
		Roles:  roles,
	}, nil
}

// AuthorizeAccess checks if a user has permission for a specific action
func (s *AuthenticationService) AuthorizeAccess(ctx context.Context, req *authpb.AuthorizeRequest) (*authpb.AuthorizeResponse, error) {
	// First validate the token
	validateReq := &authpb.ValidateTokenRequest{Token: req.GetToken()}
	validateResp, err := s.ValidateToken(ctx, validateReq)
	if err != nil {
		return nil, err
	}

	if !validateResp.Valid {
		return &authpb.AuthorizeResponse{
			Authorized: false,
			Reason:     "invalid token",
			Roles:      []string{},
		}, nil
	}

	// Check role-based authorization
	userRoles := validateResp.Roles
	requiredRole := req.GetRequiredRole()

	authorized := false
	if requiredRole == "" {
		authorized = true // No specific role required
	} else {
		for _, role := range userRoles {
			if role == requiredRole || role == "admin" { // Admin can access everything
				authorized = true
				break
			}
		}
	}

	reason := "authorized"
	if !authorized {
		reason = fmt.Sprintf("insufficient privileges: required role '%s'", requiredRole)
	}

	return &authpb.AuthorizeResponse{
		Authorized: authorized,
		Reason:     reason,
		Roles:      userRoles,
	}, nil
}

// GenerateToken creates new tokens for a user with specific roles
func (s *AuthenticationService) GenerateToken(ctx context.Context, req *authpb.GenerateTokenRequest) (*authpb.GenerateTokenResponse, error) {
	expiry := time.Duration(req.GetExpiresIn()) * time.Second
	if expiry == 0 {
		expiry = s.tokenExpiry
	}

	accessToken, err := s.generateToken(req.GetUserId(), req.GetRoles(), expiry, req.GetTokenType())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate token: %v", err)
	}

	refreshToken, err := s.generateToken(req.GetUserId(), req.GetRoles(), s.refreshExpiry, "refresh")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate refresh token: %v", err)
	}

	return &authpb.GenerateTokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(expiry.Seconds()),
		TokenType:    req.GetTokenType(),
	}, nil
}

// RefreshToken exchanges a refresh token for new access tokens
func (s *AuthenticationService) RefreshToken(ctx context.Context, req *authpb.RefreshTokenRequest) (*authpb.RefreshTokenResponse, error) {
	// Validate refresh token
	validateReq := &authpb.ValidateTokenRequest{Token: req.GetRefreshToken()}
	validateResp, err := s.ValidateToken(ctx, validateReq)
	if err != nil {
		return nil, err
	}

	if !validateResp.Valid {
		return nil, status.Errorf(codes.Unauthenticated, "invalid refresh token")
	}

	// Generate new tokens
	accessToken, err := s.generateToken(validateResp.UserId, validateResp.Roles, s.tokenExpiry, "access")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate access token: %v", err)
	}

	refreshToken, err := s.generateToken(validateResp.UserId, validateResp.Roles, s.refreshExpiry, "refresh")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate refresh token: %v", err)
	}

	return &authpb.RefreshTokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(s.tokenExpiry.Seconds()),
	}, nil
}

// RevokeToken invalidates a token making it unusable
func (s *AuthenticationService) RevokeToken(ctx context.Context, req *authpb.RevokeTokenRequest) (*authpb.RevokeTokenResponse, error) {
	// In a real implementation, you'd add the token to a blacklist
	// or store revoked tokens in a database

	// For now, just validate the token exists
	validateReq := &authpb.ValidateTokenRequest{Token: req.GetToken()}
	validateResp, err := s.ValidateToken(ctx, validateReq)
	if err != nil {
		return nil, err
	}

	if !validateResp.Valid {
		return &authpb.RevokeTokenResponse{
			Success: false,
			Message: "token is already invalid or expired",
		}, nil
	}

	// In production: add to blacklist, update database, etc.
	return &authpb.RevokeTokenResponse{
		Success: true,
		Message: "token revoked successfully",
	}, nil
}

// generateToken creates a JWT token with the specified claims
func (s *AuthenticationService) generateToken(userID string, roles []string, expiry time.Duration, tokenType string) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"user_id":    userID,
		"roles":      roles,
		"token_type": tokenType,
		"iat":        now.Unix(),
		"exp":        now.Add(expiry).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(s.rsaPrivKey)
}

// Start starts both gRPC and HTTP servers
func (s *AuthenticationService) Start(grpcPort, httpPort int) error {
	// Start gRPC server
	go func() {
		lis, err := net.Listen("tcp", fmt.Sprintf(":%d", grpcPort))
		if err != nil {
			log.Fatalf("Failed to listen on gRPC port %d: %v", grpcPort, err)
		}

		grpcServer := grpc.NewServer()
		authpb.RegisterAuthServiceServer(grpcServer, s)

		log.Printf("Auth gRPC server listening on port %d", grpcPort)
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("Failed to serve gRPC: %v", err)
		}
	}()

	// Start HTTP server with basic endpoints
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "healthy", "service": "auth"}`))
	})

	http.HandleFunc("/login", s.httpLoginHandler)
	http.HandleFunc("/validate", s.httpValidateHandler)

	log.Printf("Auth HTTP server listening on port %d", httpPort)
	return http.ListenAndServe(fmt.Sprintf(":%d", httpPort), nil)
}

// HTTP handlers for basic REST API
func (s *AuthenticationService) httpLoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req authpb.LoginRequest
	// In production, properly parse JSON request body
	username := r.FormValue("username")
	password := r.FormValue("password")

	req.Username = username
	req.Password = password

	resp, err := s.Login(r.Context(), &req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	// In production, use proper JSON marshaling
	fmt.Fprintf(w, `{"access_token":"%s","refresh_token":"%s","expires_in":%d}`,
		resp.AccessToken, resp.RefreshToken, resp.ExpiresIn)
}

func (s *AuthenticationService) httpValidateHandler(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	if token == "" {
		http.Error(w, "Missing authorization header", http.StatusUnauthorized)
		return
	}

	// Remove "Bearer " prefix if present
	if len(token) > 7 && token[:7] == "Bearer " {
		token = token[7:]
	}

	req := &authpb.ValidateTokenRequest{Token: token}
	resp, err := s.ValidateToken(r.Context(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if resp.Valid {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"valid":true,"user_id":"%s","roles":%v}`,
			resp.UserId, resp.Roles)
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"valid":false}`))
	}
}