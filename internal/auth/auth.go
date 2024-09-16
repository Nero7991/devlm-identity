package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"
	"unicode"
	"strings"

	"github.com/Nero7991/devlm/devlm-identity/pkg/database"
	"github.com/Nero7991/devlm/devlm-identity/pkg/models"
	"github.com/Nero7991/devlm/devlm-identity/internal/user"
	"github.com/Nero7991/devlm/devlm-identity/internal/ssh"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"golang.org/x/time/rate"
	"github.com/google/uuid"
)

type Service struct {
	db           database.PostgresDB
	loginLimiter *rate.Limiter
	logger       *log.Logger
	registerLimiter *rate.Limiter
	resetPasswordLimiter *rate.Limiter
	userService *user.Service
	sshService *ssh.Service
}

func NewService(db database.PostgresDB, logger *log.Logger, userService *user.Service, sshService *ssh.Service) *Service {
	return &Service{
		db:           db,
		loginLimiter: rate.NewLimiter(rate.Every(time.Minute), 5),
		logger:       logger,
		registerLimiter: rate.NewLimiter(rate.Every(time.Hour), 10),
		resetPasswordLimiter: rate.NewLimiter(rate.Every(time.Hour), 3),
		userService: userService,
		sshService: sshService,
	}
}

func RegisterRoutes(router *mux.Router, service *Service) {
	router.HandleFunc("/auth/register", RateLimitMiddleware(service.registerLimiter, service.Register)).Methods("POST")
	router.HandleFunc("/auth/login", RateLimitMiddleware(service.loginLimiter, service.Login)).Methods("POST")
	router.HandleFunc("/auth/forgot-password", RateLimitMiddleware(service.resetPasswordLimiter, service.ForgotPassword)).Methods("POST")
	router.HandleFunc("/auth/reset-password", service.ResetPassword).Methods("POST")
	router.HandleFunc("/auth/logout", service.AuthMiddleware(service.Logout)).Methods("POST")
	router.HandleFunc("/auth/refresh", service.RefreshToken).Methods("POST")
	router.HandleFunc("/auth/change-password", service.AuthMiddleware(service.ChangePassword)).Methods("POST")
	router.HandleFunc("/auth/assign-role", service.AdminMiddleware(http.HandlerFunc(service.AssignRole))).Methods("POST")
	router.HandleFunc("/auth/ssh-keys", service.AuthMiddleware(service.ListSSHKeys)).Methods("GET")
	router.HandleFunc("/auth/ssh-keys", service.AuthMiddleware(service.AddSSHKey)).Methods("POST")
	router.HandleFunc("/auth/ssh-keys/{id}", service.AuthMiddleware(service.DeleteSSHKey)).Methods("DELETE")
	router.HandleFunc("/auth/profile", service.AuthMiddleware(service.GetUserProfile)).Methods("GET")
	router.HandleFunc("/api/v1/users/profile", service.AuthMiddleware(service.GetUserProfile)).Methods("GET")
	router.HandleFunc("/api/v1/users/refresh-token", service.RefreshToken).Methods("POST")
	router.HandleFunc("/api/v1/users/change-password", service.AuthMiddleware(service.ChangePassword)).Methods("POST")
}

func (s *Service) AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			s.logger.Println("Missing authorization token")
			http.Error(w, "Missing authorization token", http.StatusUnauthorized)
			return
		}

		claims, err := ValidateToken(tokenString)
		if err != nil {
			s.logger.Printf("Invalid token: %v", err)
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		userID, ok := (*claims)["user_id"].(string)
		if !ok {
			s.logger.Println("Invalid user ID in claims")
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		uid, err := uuid.Parse(userID)
		if err != nil {
			s.logger.Printf("Invalid UUID format for user ID: %v", err)
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "userID", uid)
		ctx = context.WithValue(ctx, "claims", claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

func (s *Service) AdminMiddleware(next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.logger.Println("AdminMiddleware: Starting")
		claims, ok := r.Context().Value("claims").(*jwt.MapClaims)
		if !ok {
			s.logger.Println("AdminMiddleware: Failed to get user claims from context")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		s.logger.Printf("AdminMiddleware: Claims from context: %+v", *claims)

		role, ok := (*claims)["role"].(string)
		if !ok || role != "admin" {
			s.logger.Printf("AdminMiddleware: User is not an admin. Role: %s", role)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		s.logger.Println("AdminMiddleware: User is an admin, proceeding")
		next.ServeHTTP(w, r)
	}
}

func (s *Service) Login(w http.ResponseWriter, r *http.Request) {
	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		s.logger.Printf("Error reading request body: %v", err)
		http.Error(w, "Error reading request body", http.StatusBadRequest)
		return
	}
	s.logger.Printf("Raw request body: %s", string(bodyBytes))

	var creds struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.Unmarshal(bodyBytes, &creds); err != nil {
		s.logger.Printf("Invalid JSON in request body: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	s.logger.Printf("Login attempt for username: %s or email: %s", creds.Username, creds.Email)

	var user *models.User
	var loginErr error

	if creds.Email != "" {
		user, loginErr = s.userService.GetUserByEmail(creds.Email)
	} else if creds.Username != "" {
		user, loginErr = s.userService.GetUserByUsername(creds.Username)
	} else {
		s.logger.Println("No username or email provided")
		http.Error(w, "Username or email is required", http.StatusBadRequest)
		return
	}

	if loginErr != nil {
		if loginErr == database.ErrUserNotFound {
			s.logger.Printf("Invalid credentials: user not found")
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}
		s.logger.Printf("Error retrieving user: %v", loginErr)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if user == nil {
		s.logger.Printf("User is nil")
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	s.logger.Printf("Verifying password for user: %s", user.Username)
	if err := user.VerifyPassword(creds.Password); err != nil {
		s.logger.Printf("Invalid password for user %s: %v", user.Username, err)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	token, err := generateToken(user)
	if err != nil {
		s.logger.Printf("Failed to generate token: %v", err)
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	refreshToken, err := generateRefreshToken(user)
	if err != nil {
		s.logger.Printf("Failed to generate refresh token: %v", err)
		http.Error(w, "Failed to generate refresh token", http.StatusInternalServerError)
		return
	}

	s.logger.Printf("Login successful for user: %s, Role: %s", user.Username, user.Role)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"token": token, "refresh_token": refreshToken})
}

func (s *Service) Register(w http.ResponseWriter, r *http.Request) {
	s.logger.Printf("Received registration request from IP: %s", r.RemoteAddr)
	
	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		s.logger.Printf("Error reading request body: %v", err)
		http.Error(w, "Error reading request body", http.StatusBadRequest)
		return
	}
	s.logger.Printf("Raw request body: %s", string(bodyBytes))
	
	var userInput struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	
	if err := json.Unmarshal(bodyBytes, &userInput); err != nil {
		s.logger.Printf("Invalid JSON in request body: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	
	s.logger.Printf("Parsed user input: username=%s, email=%s, role=%s", userInput.Username, userInput.Email, userInput.Role)

	existingUser, err := s.userService.GetUserByEmail(userInput.Email)
	if err != nil && err != database.ErrUserNotFound {
		s.logger.Printf("Error checking existing email: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if existingUser != nil {
		s.logger.Printf("Email already exists: %s", userInput.Email)
		http.Error(w, "Email already exists", http.StatusConflict)
		return
	}

	existingUser, err = s.userService.GetUserByUsername(userInput.Username)
	if err != nil && err != database.ErrUserNotFound {
		s.logger.Printf("Error checking existing username: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if existingUser != nil {
		s.logger.Printf("Username already exists: %s", userInput.Username)
		http.Error(w, "Username already exists", http.StatusConflict)
		return
	}

	user, err := models.NewUser(userInput.Username, userInput.Email, userInput.Password)
	if err != nil {
		s.logger.Printf("Failed to create user: %v", err)
		http.Error(w, fmt.Sprintf("Failed to create user: %v", err), http.StatusBadRequest)
		return
	}

	if userInput.Role != "" {
		if err := user.UpdateRole(userInput.Role); err != nil {
			s.logger.Printf("Invalid role: %v", err)
			http.Error(w, fmt.Sprintf("Invalid role: %v", err), http.StatusBadRequest)
			return
		}
	} else {
		user.Role = "user" // Set default role if not provided
	}

	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()

	s.logger.Printf("Attempting to create user in database: username=%s, email=%s, role=%s", user.Username, user.Email, user.Role)
	if err := s.db.CreateUser(user); err != nil {
		s.logger.Printf("Failed to create user in database: %v", err)
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	s.logger.Printf("User created successfully: username=%s, email=%s, role=%s, id=%s", user.Username, user.Email, user.Role, user.ID)

	w.WriteHeader(http.StatusCreated)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "User created successfully"})
}

func (s *Service) Logout(w http.ResponseWriter, r *http.Request) {
	s.logger.Println("User logged out")
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Logged out successfully"})
}

func (s *Service) RefreshToken(w http.ResponseWriter, r *http.Request) {
	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		s.logger.Printf("Error reading request body: %v", err)
		http.Error(w, "Error reading request body", http.StatusBadRequest)
		return
	}
	s.logger.Printf("Raw request body: %s", string(bodyBytes))

	var refreshRequest struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.Unmarshal(bodyBytes, &refreshRequest); err != nil {
		s.logger.Printf("Invalid JSON in request body: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	claims, err := ValidateRefreshToken(refreshRequest.RefreshToken)
	if err != nil {
		s.logger.Printf("Invalid refresh token: %v", err)
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	userID, ok := (*claims)["user_id"].(string)
	if !ok {
		s.logger.Printf("Invalid token claims")
		http.Error(w, "Invalid token claims", http.StatusUnauthorized)
		return
	}

	uid, err := uuid.Parse(userID)
	if err != nil {
		s.logger.Printf("Invalid UUID format for user ID: %v", err)
		http.Error(w, "Invalid token claims", http.StatusUnauthorized)
		return
	}

	user, err := s.db.GetUserByID(uid)
	if err != nil {
		s.logger.Printf("User not found: %v", err)
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}

	newToken, err := generateToken(user)
	if err != nil {
		s.logger.Printf("Failed to generate new token: %v", err)
		http.Error(w, "Failed to generate new token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"token": newToken})
}

func (s *Service) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		s.logger.Printf("Error reading request body: %v", err)
		http.Error(w, "Error reading request body", http.StatusBadRequest)
		return
	}
	s.logger.Printf("Raw request body: %s", string(bodyBytes))

	var forgotPasswordRequest struct {
		Email string `json:"email"`
	}

	if err := json.Unmarshal(bodyBytes, &forgotPasswordRequest); err != nil {
		s.logger.Printf("Invalid JSON in request body: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	s.logger.Printf("Forgot password request for email: %s", forgotPasswordRequest.Email)

	user, err := s.userService.GetUserByEmail(forgotPasswordRequest.Email)
	if err != nil {
		if err == database.ErrUserNotFound {
			s.logger.Printf("User not found for email %s", forgotPasswordRequest.Email)
		} else {
			s.logger.Printf("Error retrieving user: %v", err)
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"message": "If the email is registered, a password reset link will be sent."})
		return
	}

	resetToken, err := generateResetToken()
	if err != nil {
		s.logger.Printf("Failed to generate reset token: %v", err)
		http.Error(w, "Failed to process password reset request", http.StatusInternalServerError)
		return
	}

	expirationTime := time.Now().Add(24 * time.Hour)
	if err := s.db.StoreResetToken(user.ID, resetToken, expirationTime); err != nil {
		s.logger.Printf("Failed to store reset token: %v", err)
		http.Error(w, "Failed to process password reset request", http.StatusInternalServerError)
		return
	}

	s.logger.Printf("Generated reset token for user %s: %s (expires at %v)", user.ID, resetToken, expirationTime)

	// TODO: Send email with reset token
	// For now, we'll just log the reset token
	s.logger.Printf("Reset token for user %s: %s", user.ID, resetToken)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "If the email is registered, a password reset link will be sent."})
}

func (s *Service) ResetPassword(w http.ResponseWriter, r *http.Request) {
	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		s.logger.Printf("Error reading request body: %v", err)
		http.Error(w, "Error reading request body", http.StatusBadRequest)
		return
	}
	s.logger.Printf("Raw request body: %s", string(bodyBytes))

	var resetPasswordRequest struct {
		Email       string `json:"email"`
		ResetToken  string `json:"token"`
		NewPassword string `json:"new_password"`
	}

	if err := json.Unmarshal(bodyBytes, &resetPasswordRequest); err != nil {
		s.logger.Printf("Invalid JSON in request body: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	s.logger.Printf("Attempting to reset password for email: %s with token: %s", resetPasswordRequest.Email, resetPasswordRequest.ResetToken)

	user, err := s.db.GetUserByResetToken(resetPasswordRequest.ResetToken)
	if err != nil {
		s.logger.Printf("Invalid or expired reset token: %v", err)
		http.Error(w, "Invalid or expired reset token", http.StatusBadRequest)
		return
	}

	s.logger.Printf("User found for reset token: ID=%s, Username=%s", user.ID, user.Username)

	if err := validatePassword(resetPasswordRequest.NewPassword); err != nil {
		s.logger.Printf("Invalid new password: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := user.UpdatePassword(resetPasswordRequest.NewPassword); err != nil {
		s.logger.Printf("Failed to update user password: %v", err)
		http.Error(w, "Failed to update password", http.StatusInternalServerError)
		return
	}

	user.UpdatedAt = time.Now()

	s.logger.Printf("Password updated successfully for user ID=%s", user.ID)

	if err := s.db.UpdateUserPassword(user.ID, user.PasswordHash); err != nil {
		s.logger.Printf("Failed to update user in database: %v", err)
		http.Error(w, "Failed to update password", http.StatusInternalServerError)
		return
	}

	if err := s.db.InvalidateResetToken(resetPasswordRequest.ResetToken); err != nil {
		s.logger.Printf("Failed to invalidate reset token: %v", err)
		// Continue execution as the password has been reset successfully
	}

	s.logger.Printf("Password reset successful for user ID=%s", user.ID)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Password reset successfully"})
}

func (s *Service) ChangePassword(w http.ResponseWriter, r *http.Request) {
	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		s.logger.Printf("Error reading request body: %v", err)
		http.Error(w, "Error reading request body", http.StatusBadRequest)
		return
	}
	s.logger.Printf("Raw request body: %s", string(bodyBytes))

	var changePasswordRequest struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}

	if err := json.Unmarshal(bodyBytes, &changePasswordRequest); err != nil {
		s.logger.Printf("Invalid JSON in request body: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	userID, ok := r.Context().Value("userID").(uuid.UUID)
	if !ok {
		s.logger.Println("Failed to get user ID from context")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	user, err := s.db.GetUserByID(userID)
	if err != nil {
		s.logger.Printf("Failed to get user: %v", err)
		http.Error(w, "Failed to change password", http.StatusInternalServerError)
		return
	}

	s.logger.Printf("Attempting to change password for user ID=%s", userID)

	if err := user.VerifyPassword(changePasswordRequest.CurrentPassword); err != nil {
		s.logger.Printf("Invalid old password for user ID=%s: %v", userID, err)
		http.Error(w, "Invalid old password", http.StatusUnauthorized)
		return
	}

	if err := validatePassword(changePasswordRequest.NewPassword); err != nil {
		s.logger.Printf("Invalid new password: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := user.UpdatePassword(changePasswordRequest.NewPassword); err != nil {
		s.logger.Printf("Failed to update user password: %v", err)
		http.Error(w, "Failed to change password", http.StatusInternalServerError)
		return
	}

	user.UpdatedAt = time.Now()

	if err := s.db.UpdateUserPassword(user.ID, user.PasswordHash); err != nil {
		s.logger.Printf("Failed to update user in database: %v", err)
		http.Error(w, "Failed to change password", http.StatusInternalServerError)
		return
	}

	s.logger.Printf("Password changed successfully for user ID=%s", userID)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Password changed successfully"})
}

func (s *Service) AssignRole(w http.ResponseWriter, r *http.Request) {
	s.logger.Println("AssignRole: Starting")

	claims, ok := r.Context().Value("claims").(*jwt.MapClaims)
	if !ok {
		s.logger.Println("AssignRole: Failed to get user claims from context")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	s.logger.Printf("AssignRole: Claims from context: %+v", *claims)

	role, ok := (*claims)["role"].(string)
	if !ok || role != "admin" {
		s.logger.Printf("AssignRole: User is not an admin. Role: %s", role)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		s.logger.Printf("AssignRole: Error reading request body: %v", err)
		http.Error(w, "Error reading request body", http.StatusBadRequest)
		return
	}
	s.logger.Printf("AssignRole: Raw request body: %s", string(bodyBytes))

	var assignRoleRequest struct {
		UserID uuid.UUID `json:"user_id"`
		Role   string    `json:"role"`
	}

	if err := json.Unmarshal(bodyBytes, &assignRoleRequest); err != nil {
		s.logger.Printf("AssignRole: Invalid JSON in request body: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	s.logger.Printf("AssignRole: Attempting to assign role '%s' to user ID %s", assignRoleRequest.Role, assignRoleRequest.UserID)

	user, err := s.db.GetUserByID(assignRoleRequest.UserID)
	if err != nil {
		s.logger.Printf("AssignRole: Failed to get user: %v", err)
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	oldRole := user.Role
	if err := user.UpdateRole(assignRoleRequest.Role); err != nil {
		s.logger.Printf("AssignRole: Failed to update user role: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	user.UpdatedAt = time.Now()

	if err := s.db.UpdateUser(user); err != nil {
		s.logger.Printf("AssignRole: Failed to update user role in database: %v", err)
		http.Error(w, "Failed to assign role", http.StatusInternalServerError)
		return
	}

	s.logger.Printf("AssignRole: Role updated successfully for user ID=%s: old role=%s, new role=%s", user.ID, oldRole, user.Role)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Role assigned successfully"})
}

func (s *Service) ListSSHKeys(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("userID").(uuid.UUID)
	if !ok {
		s.logger.Println("Failed to get user ID from context")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	keys, err := s.sshService.ListSSHKeys(userID)
	if err != nil {
		s.logger.Printf("Failed to list SSH keys: %v", err)
		http.Error(w, "Failed to list SSH keys", http.StatusInternalServerError)
		return
	}

	s.logger.Printf("Listed SSH keys for user ID=%s", userID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(keys)
}

func (s *Service) AddSSHKey(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("userID").(uuid.UUID)
	if !ok {
		s.logger.Println("Failed to get user ID from context")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		s.logger.Printf("Error reading request body: %v", err)
		http.Error(w, "Error reading request body", http.StatusBadRequest)
		return
	}
	s.logger.Printf("Raw request body: %s", string(bodyBytes))

	var keyRequest struct {
		Name      string `json:"name"`
		PublicKey string `json:"public_key"`
	}

	if err := json.Unmarshal(bodyBytes, &keyRequest); err != nil {
		s.logger.Printf("Invalid JSON in request body: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	s.logger.Printf("Adding SSH key for user ID=%s: Name=%s, PublicKey=%s", userID, keyRequest.Name, keyRequest.PublicKey)

	if err := s.sshService.AddSSHKey(userID, keyRequest.Name, keyRequest.PublicKey); err != nil {
		s.logger.Printf("Failed to add SSH key: %v", err)
		http.Error(w, "Failed to add SSH key", http.StatusInternalServerError)
		return
	}

	s.logger.Printf("SSH key added successfully for user ID=%s", userID)

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "SSH key added successfully"})
}

func (s *Service) DeleteSSHKey(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("userID").(uuid.UUID)
	if !ok {
		s.logger.Println("Failed to get user ID from context")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	keyID, err := uuid.Parse(vars["id"])
	if err != nil {
		s.logger.Printf("Invalid key ID: %v", err)
		http.Error(w, "Invalid key ID", http.StatusBadRequest)
		return
	}

	s.logger.Printf("Deleting SSH key ID=%s for user ID=%s", keyID, userID)

	if err := s.sshService.DeleteSSHKey(userID, keyID); err != nil {
		s.logger.Printf("Failed to delete SSH key: %v", err)
		http.Error(w, "Failed to delete SSH key", http.StatusInternalServerError)
		return
	}

	s.logger.Printf("Deleted SSH key ID=%s for user ID=%s", keyID, userID)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "SSH key deleted successfully"})
}

func (s *Service) GetUserProfile(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("userID").(uuid.UUID)
	if !ok {
		s.logger.Println("Failed to get user ID from context")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	user, err := s.db.GetUserByID(userID)
	if err != nil {
		s.logger.Printf("Failed to get user profile:%v", err)
		http.Error(w, "Failed to get user profile", http.StatusInternalServerError)
		return
	}

	profile := struct {
		ID        uuid.UUID `json:"id"`
		Username  string    `json:"username"`
		Email     string    `json:"email"`
		Role      string    `json:"role"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
	}{
		ID:        user.ID,
		Username:  user.Username,
		Email:     user.Email,
		Role:      user.Role,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}

	s.logger.Printf("Retrieved profile for user ID=%s", userID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(profile)
}

func generateToken(user *models.User) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":  user.ID.String(),
		"username": user.Username,
		"role":     user.Role,
		"exp":      time.Now().Add(time.Hour * 24).Unix(),
	})

	secretKey := getSecretKey()
	return token.SignedString([]byte(secretKey))
}

func generateRefreshToken(user *models.User) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": user.ID.String(),
		"exp":     time.Now().Add(time.Hour * 24 * 7).Unix(),
	})

	secretKey := getRefreshSecretKey()
	return token.SignedString([]byte(secretKey))
}

func ValidateToken(tokenString string) (*jwt.MapClaims, error) {
	log.Printf("Validating token: %s", tokenString)

	// Remove "Bearer " prefix if present
	tokenString = strings.TrimPrefix(tokenString, "Bearer ")

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			log.Printf("Unexpected signing method: %v", token.Header["alg"])
			return nil, errors.New("unexpected signing method")
		}
		return []byte(getSecretKey()), nil
	})

	if err != nil {
		log.Printf("Error parsing token: %v", err)
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		log.Printf("Token validated successfully. Claims: %+v", claims)
		return &claims, nil
	}

	log.Println("Token is invalid")
	return nil, errors.New("invalid token")
}

func ValidateRefreshToken(tokenString string) (*jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(getRefreshSecretKey()), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return &claims, nil
	}

	return nil, errors.New("invalid refresh token")
}

func getSecretKey() string {
	secretKey := os.Getenv("JWT_SECRET_KEY")
	if secretKey == "" {
		secretKey = "default-secret-key"
	}
	return secretKey
}

func getRefreshSecretKey() string {
	secretKey := os.Getenv("JWT_REFRESH_SECRET_KEY")
	if secretKey == "" {
		secretKey = "default-refresh-secret-key"
	}
	return secretKey
}

func validatePassword(password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters long")
	}

	var (
		hasUpper   bool
		hasLower   bool
		hasNumber  bool
		hasSpecial bool
	)

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	if !hasUpper || !hasLower || !hasNumber || !hasSpecial {
		return errors.New("password must contain at least one uppercase letter, one lowercase letter, one number, and one special character")
	}

	return nil
}

func generateResetToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func RateLimitMiddleware(limiter *rate.Limiter, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow() {
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	}
}

func (s *Service) GetUserByID(id uuid.UUID) (*models.User, error) {
	s.logger.Printf("Getting user by ID: %s", id)
	user, err := s.db.GetUserByID(id)
	if err != nil {
		s.logger.Printf("Error getting user by ID %s: %v", id, err)
		return nil, err
	}
	return user, nil
}

func (s *Service) UpdateUser(user *models.User) error {
	s.logger.Printf("Updating user: ID=%s, Username=%s, Role=%s", user.ID, user.Username, user.Role)
	err := s.db.UpdateUser(user)
	if err != nil {
		s.logger.Printf("Error updating user %s: %v", user.ID, err)
		return err
	}
	s.logger.Printf("User updated successfully: ID=%s", user.ID)
	return nil
}