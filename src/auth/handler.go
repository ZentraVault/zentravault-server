package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/ZentraVault/zentravault-server/src/user"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"golang.org/x/crypto/bcrypt"
)

type Handler struct {
	userRepo *user.Repository
}

func NewHandler(userRepo *user.Repository) *Handler {
	return &Handler{
		userRepo: userRepo,
	}
}

// Request body structures for register
type RegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Request body structures for login
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// AuthResponse
type AuthResponse struct {
	Success bool          `json:"success"`
	Message string        `json:"message,omitempty"`
	Token   string        `json:"token,omitempty"`
	User    *UserResponse `json:"user,omitempty"`
}

// UserResponse
type UserResponse struct {
	ID       string   `json:"id"`
	Username string   `json:"username"`
	Email    string   `json:"email"`
	Status   string   `json:"status"`
	Friends  []string `json:"friends"`
	Groups   []string `json:"groups"`
}

// Regex for mail
var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

// Regex for username
var usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]{3,20}$`)

// Check email format
func isValidEmail(email string) bool {
	return emailRegex.MatchString(email)
}

// Check username format
func isValidUsername(username string) bool {
	return usernameRegex.MatchString(username)
}

// Generate token
func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Generate a unique public ID for users
func generatePublicID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Register handles user registration
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, AuthResponse{
			Success: false,
			Message: "Invalid request body",
		})
		return
	}

	// Validate input
	if req.Username == "" || req.Email == "" || req.Password == "" {
		respondJSON(w, http.StatusBadRequest, AuthResponse{
			Success: false,
			Message: "Username, email, and password are required",
		})
		return
	}

	if !isValidUsername(req.Username) {
		respondJSON(w, http.StatusBadRequest, AuthResponse{
			Success: false,
			Message: "Username must be 3-20 characters (letters, numbers, _, -)",
		})
		return
	}

	if !isValidEmail(req.Email) {
		respondJSON(w, http.StatusBadRequest, AuthResponse{
			Success: false,
			Message: "Invalid email format",
		})
		return
	}

	if len(req.Password) < 8 {
		respondJSON(w, http.StatusBadRequest, AuthResponse{
			Success: false,
			Message: "Password must be at least 8 characters",
		})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Check if username already exists
	existingUser, err := h.userRepo.GetUserByUsername(ctx, req.Username)
	if err == nil && existingUser != nil {
		respondJSON(w, http.StatusConflict, AuthResponse{
			Success: false,
			Message: "Username already exists",
		})
		return
	}

	// Check if email already exists
	existingEmail, err := h.userRepo.GetUserByEmail(ctx, req.Email)
	if err == nil && existingEmail != nil {
		respondJSON(w, http.StatusConflict, AuthResponse{
			Success: false,
			Message: "Email already in use",
		})
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, AuthResponse{
			Success: false,
			Message: "Error creating account",
		})
		return
	}

	// Generate token and public ID
	token, err := generateToken()
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, AuthResponse{
			Success: false,
			Message: "Error creating account",
		})
		return
	}

	publicID, err := generatePublicID()
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, AuthResponse{
			Success: false,
			Message: "Error creating account",
		})
		return
	}

	// Create user
	newUser := &user.User{
		ID:       publicID,
		Username: req.Username,
		Email:    req.Email,
		Password: string(hashedPassword),
		Token:    token,
		Status:   "online",
		Friends:  []string{},
		Groups:   []string{},
	}

	if err := h.userRepo.CreateUser(ctx, newUser); err != nil {
		respondJSON(w, http.StatusInternalServerError, AuthResponse{
			Success: false,
			Message: "Error creating account",
		})
		return
	}

	// Return success response
	respondJSON(w, http.StatusCreated, AuthResponse{
		Success: true,
		Message: "Account created successfully",
		Token:   token,
		User: &UserResponse{
			ID:       newUser.ID,
			Username: newUser.Username,
			Email:    newUser.Email,
			Status:   newUser.Status,
			Friends:  newUser.Friends,
			Groups:   newUser.Groups,
		},
	})
}

// Login handles user login
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, AuthResponse{
			Success: false,
			Message: "Invalid request body",
		})
		return
	}

	// Validate input
	if req.Username == "" || req.Password == "" {
		respondJSON(w, http.StatusBadRequest, AuthResponse{
			Success: false,
			Message: "Username and password are required",
		})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Get user by username
	existingUser, err := h.userRepo.GetUserByUsername(ctx, req.Username)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			respondJSON(w, http.StatusUnauthorized, AuthResponse{
				Success: false,
				Message: "Invalid username or password",
			})
			return
		}
		respondJSON(w, http.StatusInternalServerError, AuthResponse{
			Success: false,
			Message: "Error logging in",
		})
		return
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(existingUser.Password), []byte(req.Password)); err != nil {
		respondJSON(w, http.StatusUnauthorized, AuthResponse{
			Success: false,
			Message: "Invalid username or password",
		})
		return
	}

	// Return success response with token
	respondJSON(w, http.StatusOK, AuthResponse{
		Success: true,
		Message: "Login successful",
		Token:   existingUser.Token,
		User: &UserResponse{
			ID:       existingUser.ID,
			Username: existingUser.Username,
			Email:    existingUser.Email,
			Status:   existingUser.Status,
			Friends:  existingUser.Friends,
			Groups:   existingUser.Groups,
		},
	})
}

// Validates a bearer token from the Authorization header
func (h *Handler) ValidateToken(w http.ResponseWriter, r *http.Request) {
	token := extractToken(r)
	if token == "" {
		respondJSON(w, http.StatusUnauthorized, AuthResponse{
			Success: false,
			Message: "No token provided",
		})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Find user by token
	u, err := h.userRepo.GetUserByToken(ctx, token)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			respondJSON(w, http.StatusUnauthorized, AuthResponse{
				Success: false,
				Message: "Invalid token",
			})
			return
		}
		respondJSON(w, http.StatusInternalServerError, AuthResponse{
			Success: false,
			Message: "Error validating token",
		})
		return
	}

	respondJSON(w, http.StatusOK, AuthResponse{
		Success: true,
		Message: "Token is valid",
		User: &UserResponse{
			ID:       u.ID,
			Username: u.Username,
			Email:    u.Email,
			Status:   u.Status,
			Friends:  u.Friends,
			Groups:   u.Groups,
		},
	})
}

// Extracts the bearer token from the Authorization header
func extractToken(r *http.Request) string {
	bearerToken := r.Header.Get("Authorization")
	if bearerToken == "" {
		return ""
	}

	parts := strings.Split(bearerToken, " ")
	if len(parts) == 2 && parts[0] == "Bearer" {
		return parts[1]
	}

	return ""
}

// JSON response
func respondJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(payload)
}
