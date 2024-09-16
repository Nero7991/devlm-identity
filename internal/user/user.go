package user

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"time"

	"github.com/Nero7991/devlm/devlm-identity/internal/ssh"
	"github.com/Nero7991/devlm/devlm-identity/pkg/database"
	"github.com/Nero7991/devlm/devlm-identity/pkg/models"
	"github.com/gorilla/mux"
	"github.com/google/uuid"
)

type Service struct {
	db         database.PostgresDB
	logger     *log.Logger
	sshService *ssh.Service
}

func NewService(db database.PostgresDB, logger *log.Logger, sshService *ssh.Service) *Service {
	return &Service{db: db, logger: logger, sshService: sshService}
}

func RegisterRoutes(router *mux.Router, service *Service) {
	router.HandleFunc("/users", service.CreateUser).Methods("POST")
	router.HandleFunc("/users/{id}", service.GetUser).Methods("GET")
	router.HandleFunc("/users", service.ListUsers).Methods("GET")
	router.HandleFunc("/users/{id}", service.UpdateUser).Methods("PUT")
	router.HandleFunc("/users/{id}", service.DeleteUser).Methods("DELETE")
	router.HandleFunc("/users/{id}/change-password", service.ChangePassword).Methods("POST")
	router.HandleFunc("/users/{id}/update-role", service.UpdateUserRole).Methods("PATCH")
	router.HandleFunc("/users/forgot-password", service.ForgotPassword).Methods("POST")
	router.HandleFunc("/users/reset-password", service.ResetPassword).Methods("POST")
	router.HandleFunc("/users/{id}/role", service.GetUserRole).Methods("GET")
	router.HandleFunc("/users/{id}/assign-role", service.AssignUserRole).Methods("POST")
}

func (s *Service) CreateUser(w http.ResponseWriter, r *http.Request) {
	s.logger.Println("CreateUser endpoint called")

	var newUser models.User
	if err := json.NewDecoder(r.Body).Decode(&newUser); err != nil {
		s.logger.Printf("Failed to decode request body: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	s.logger.Printf("Received request to create user: %s", newUser.Username)

	if err := validateUser(&newUser); err != nil {
		s.logger.Printf("User validation failed: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.logger.Printf("Creating new user with username: %s, email: %s", newUser.Username, newUser.Email)
	createdUser, err := models.NewUser(newUser.Username, newUser.Email, newUser.Password)
	if err != nil {
		s.logger.Printf("Failed to create user instance: %v", err)
		if errors.Is(err, models.ErrInvalidPassword) {
			s.logger.Printf("Password validation failed: %v", err)
			http.Error(w, fmt.Sprintf("Invalid password: %v", err), http.StatusBadRequest)
		} else {
			http.Error(w, "Failed to process user data", http.StatusInternalServerError)
		}
		return
	}

	if newUser.Role != "" {
		s.logger.Printf("Setting user role to: %s", newUser.Role)
		if err := createdUser.UpdateRole(newUser.Role); err != nil {
			s.logger.Printf("Invalid role: %v", err)
			http.Error(w, "Invalid role", http.StatusBadRequest)
			return
		}
	}

	createdUser.CreatedAt = time.Now()
	createdUser.UpdatedAt = time.Now()
	createdUser.CreatorID = newUser.CreatorID

	s.logger.Printf("Creating user in database: ID=%s, Username=%s, Email=%s, Role=%s, CreatedAt=%s, UpdatedAt=%s, CreatorID=%v",
		createdUser.ID, createdUser.Username, createdUser.Email, createdUser.Role, createdUser.CreatedAt, createdUser.UpdatedAt, createdUser.CreatorID)

	if err := s.db.CreateUser(createdUser); err != nil {
		s.logger.Printf("Failed to create user in database: %v", err)
		if err == database.ErrDuplicateKey {
			http.Error(w, "Username or email already exists", http.StatusConflict)
		} else {
			s.logger.Printf("Detailed error: %+v", err)
			http.Error(w, "Failed to create user", http.StatusInternalServerError)
		}
		return
	}

	s.logger.Printf("User created successfully: ID=%s, Username=%s, Role=%s, CreatedAt=%s, CreatorID=%v", createdUser.ID, createdUser.Username, createdUser.Role, createdUser.CreatedAt, createdUser.CreatorID)

	w.WriteHeader(http.StatusCreated)
	w.Header().Set("Content-Type", "application/json")
	response := map[string]interface{}{
		"message":    "User created successfully",
		"user_id":    createdUser.ID,
		"role":       createdUser.Role,
		"created_at": createdUser.CreatedAt,
		"creator_id": createdUser.CreatorID,
	}
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.logger.Printf("Failed to encode response: %v", err)
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}

	s.logger.Println("CreateUser endpoint completed successfully")
}

func (s *Service) GetUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := uuid.Parse(vars["id"])
	if err != nil {
		s.logger.Printf("Invalid user ID: %s", vars["id"])
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	user, err := s.db.GetUserByID(id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.logger.Printf("User not found: %s", id)
			http.Error(w, "User not found", http.StatusNotFound)
		} else {
			s.logger.Printf("Failed to get user: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	user.PasswordHash = ""

	s.logger.Printf("Retrieved user: ID=%s, Username=%s, Role=%s, CreatedAt=%s, UpdatedAt=%s, DeletedAt=%v, CreatorID=%v",
		user.ID, user.Username, user.Role, user.CreatedAt, user.UpdatedAt, user.DeletedAt, user.CreatorID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

func (s *Service) ListUsers(w http.ResponseWriter, r *http.Request) {
	limit := 10
	offset := 0

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		parsedLimit, err := uuid.Parse(limitStr)
		if err == nil {
			limit = int(parsedLimit.ID())
			if limit <= 0 || limit > 100 {
				limit = 10
			}
		}
	}

	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		parsedOffset, err := uuid.Parse(offsetStr)
		if err == nil {
			offset = int(parsedOffset.ID())
			if offset < 0 {
				offset = 0
			}
		}
	}

	users, err := s.db.ListUsers(limit, offset)
	if err != nil {
		s.logger.Printf("Failed to list users: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	for i := range users {
		users[i].PasswordHash = ""
	}

	s.logger.Printf("Listed %d users", len(users))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

func (s *Service) UpdateUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := uuid.Parse(vars["id"])
	if err != nil {
		s.logger.Printf("Invalid user ID: %s", vars["id"])
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	var updatedUser models.User
	if err := json.NewDecoder(r.Body).Decode(&updatedUser); err != nil {
		s.logger.Printf("Failed to decode request body: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := validateUser(&updatedUser); err != nil {
		s.logger.Printf("User validation failed: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	existingUser, err := s.db.GetUserByID(id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.logger.Printf("User not found: %s", id)
			http.Error(w, "User not found", http.StatusNotFound)
		} else {
			s.logger.Printf("Failed to get user: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	existingUser.Username = updatedUser.Username
	existingUser.Email = updatedUser.Email
	existingUser.UpdatedAt = time.Now()
	if updatedUser.Role != "" {
		if err := existingUser.UpdateRole(updatedUser.Role); err != nil {
			s.logger.Printf("Invalid role: %v", err)
			http.Error(w, "Invalid role", http.StatusBadRequest)
			return
		}
	}

	if updatedUser.Password != "" {
		if err := existingUser.UpdatePassword(updatedUser.Password); err != nil {
			s.logger.Printf("Failed to update password: %v", err)
			http.Error(w, "Failed to process password", http.StatusInternalServerError)
			return
		}
	}

	s.logger.Printf("Updating user: ID=%s, Username=%s, Email=%s, Role=%s, UpdatedAt=%s",
		existingUser.ID, existingUser.Username, existingUser.Email, existingUser.Role, existingUser.UpdatedAt)

	if err := s.db.UpdateUser(existingUser); err != nil {
		s.logger.Printf("Failed to update user: %v", err)
		if err == database.ErrDuplicateKey {
			http.Error(w, "Username or email already exists", http.StatusConflict)
		} else {
			http.Error(w, "Failed to update user", http.StatusInternalServerError)
		}
		return
	}

	s.logger.Printf("User updated successfully: ID=%s, Username=%s, Role=%s, UpdatedAt=%s", existingUser.ID, existingUser.Username, existingUser.Role, existingUser.UpdatedAt)

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "User updated successfully"})
}

func (s *Service) DeleteUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := uuid.Parse(vars["id"])
	if err != nil {
		s.logger.Printf("Invalid user ID: %s", vars["id"])
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	s.logger.Printf("Attempting to delete user: ID=%s", id)

	if err := s.db.DeleteUser(id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.logger.Printf("User not found: %s", id)
			http.Error(w, "User not found", http.StatusNotFound)
		} else {
			s.logger.Printf("Failed to delete user: %v", err)
			http.Error(w, "Failed to delete user", http.StatusInternalServerError)
		}
		return
	}

	s.logger.Printf("User deleted successfully: ID=%s", id)

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "User deleted successfully"})
}

func (s *Service) GetUserByUsername(username string) (*models.User, error) {
	s.logger.Printf("Getting user by username: %s", username)
	user, err := s.db.GetUserByUsername(username)
	if err != nil {
		s.logger.Printf("Failed to get user by username: %v", err)
		return nil, err
	}
	s.logger.Printf("Retrieved user by username: ID=%s, Username=%s, Role=%s", user.ID, user.Username, user.Role)
	return user, nil
}

func (s *Service) GetUserByEmail(email string) (*models.User, error) {
	s.logger.Printf("Getting user by email: %s", email)
	user, err := s.db.GetUserByEmail(email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.logger.Printf("User not found for email: %s", email)
			return nil, database.ErrUserNotFound
		}
		s.logger.Printf("Failed to get user by email: %v", err)
		return nil, err
	}
	s.logger.Printf("Retrieved user by email: ID=%s, Username=%s, Role=%s", user.ID, user.Username, user.Role)
	return user, nil
}

func (s *Service) ChangePassword(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := uuid.Parse(vars["id"])
	if err != nil {
		s.logger.Printf("Invalid user ID: %s", vars["id"])
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	var passwordChange struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&passwordChange); err != nil {
		s.logger.Printf("Failed to decode request body: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	user, err := s.db.GetUserByID(id)
	if err != nil {
		s.logger.Printf("Failed to get user: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if err := user.VerifyPassword(passwordChange.OldPassword); err != nil {
		s.logger.Printf("Invalid old password for user ID %s", id)
		http.Error(w, "Invalid old password", http.StatusUnauthorized)
		return
	}

	if err := user.UpdatePassword(passwordChange.NewPassword); err != nil {
		s.logger.Printf("Failed to update password: %v", err)
		http.Error(w, "Failed to update password", http.StatusInternalServerError)
		return
	}

	user.UpdatedAt = time.Now()

	s.logger.Printf("Changing password for user: ID=%s, Username=%s", user.ID, user.Username)

	if err := s.db.UpdateUser(user); err != nil {
		s.logger.Printf("Failed to save updated user: %v", err)
		http.Error(w, "Failed to update password", http.StatusInternalServerError)
		return
	}

	s.logger.Printf("Password changed successfully for user ID=%s", user.ID)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Password changed successfully"})
}

func (s *Service) UpdateUserRole(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := uuid.Parse(vars["id"])
	if err != nil {
		s.logger.Printf("Invalid user ID: %s", vars["id"])
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	var roleUpdate struct {
		Role string `json:"role"`
	}

	if err := json.NewDecoder(r.Body).Decode(&roleUpdate); err != nil {
		s.logger.Printf("Failed to decode request body: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	user, err := s.db.GetUserByID(id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.logger.Printf("User not found: %s", id)
			http.Error(w, "User not found", http.StatusNotFound)
		} else {
			s.logger.Printf("Failed to get user: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	if err := user.UpdateRole(roleUpdate.Role); err != nil {
		s.logger.Printf("Invalid role: %v", err)
		http.Error(w, "Invalid role", http.StatusBadRequest)
		return
	}

	user.UpdatedAt = time.Now()

	s.logger.Printf("Updating user role: ID=%s, Username=%s, NewRole=%s", user.ID, user.Username, user.Role)

	if err := s.db.UpdateUser(user); err != nil {
		s.logger.Printf("Failed to update user role: %v", err)
		http.Error(w, "Failed to update user role", http.StatusInternalServerError)
		return
	}

	s.logger.Printf("User role updated successfully: ID=%s, Username=%s, NewRole=%s, UpdatedAt=%s", user.ID, user.Username, user.Role, user.UpdatedAt)

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "User role updated successfully"})
}

func (s *Service) GetUserRole(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := uuid.Parse(vars["id"])
	if err != nil {
		s.logger.Printf("Invalid user ID: %s", vars["id"])
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	s.logger.Printf("GetUserRole called for user ID: %s", id)

	user, err := s.db.GetUserByID(id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.logger.Printf("User not found: %s", id)
			http.Error(w, "User not found", http.StatusNotFound)
		} else {
			s.logger.Printf("Failed to get user: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	s.logger.Printf("Retrieved role for user: ID=%s, Username=%s, Role=%s", user.ID, user.Username, user.Role)

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"role": user.Role})
}

func (s *Service) GetUserByID(id uuid.UUID) (*models.User, error) {
	s.logger.Printf("Getting user by ID: %s", id)
	user, err := s.db.GetUserByID(id)
	if err != nil {
		s.logger.Printf("Error getting user by ID %s: %v", id, err)
		return nil, err
	}
	s.logger.Printf("User retrieved successfully: ID=%s, Username=%s, Role=%s", user.ID, user.Username, user.Role)
	return user, nil
}

func (s *Service) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var forgotPasswordRequest struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&forgotPasswordRequest); err != nil {
		s.logger.Printf("Invalid request body: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	s.logger.Printf("Forgot password request for email: %s", forgotPasswordRequest.Email)

	user, err := s.GetUserByEmail(forgotPasswordRequest.Email)
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

	// TODO: Implement email sending functionality here
	// For now, we'll just log the reset token
	s.logger.Printf("Reset token for user %s: %s", user.ID, resetToken)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "If the email is registered, a password reset link will be sent."})
}

func (s *Service) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var resetPasswordRequest struct {
		Email       string `json:"email"`
		ResetToken  string `json:"token"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&resetPasswordRequest); err != nil {
		s.logger.Printf("Invalid request body: %v", err)
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
	}

	s.logger.Printf("Password reset successful for user ID=%s", user.ID)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Password reset successfully"})
}

func (s *Service) AssignUserRole(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := uuid.Parse(vars["id"])
	if err != nil {
		s.logger.Printf("Invalid user ID: %s", vars["id"])
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	var roleAssignment struct {
		Role string `json:"role"`
	}

	if err := json.NewDecoder(r.Body).Decode(&roleAssignment); err != nil {
		s.logger.Printf("Failed to decode request body: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	user, err := s.db.GetUserByID(id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.logger.Printf("User not found: %s", id)
			http.Error(w, "User not found", http.StatusNotFound)
		} else {
			s.logger.Printf("Failed to get user: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	if err := user.UpdateRole(roleAssignment.Role); err != nil {
		s.logger.Printf("Invalid role: %v", err)
		http.Error(w, "Invalid role", http.StatusBadRequest)
		return
	}

	user.UpdatedAt = time.Now()

	s.logger.Printf("Assigning role to user: ID=%s, Username=%s, NewRole=%s", user.ID, user.Username, user.Role)

	if err := s.db.UpdateUser(user); err != nil {
		s.logger.Printf("Failed to update user role: %v", err)
		http.Error(w, "Failed to assign user role", http.StatusInternalServerError)
		return
	}

	s.logger.Printf("User role assigned successfully: ID=%s, Username=%s, NewRole=%s, UpdatedAt=%s", user.ID, user.Username, user.Role, user.UpdatedAt)

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "User role assigned successfully", "role": user.Role})
}

func validateUser(user *models.User) error {
	if !isValidUsername(user.Username) {
		return errors.New("invalid username format")
	}
	if !isValidEmail(user.Email) {
		return errors.New("invalid email format")
	}
	return nil
}

func isValidUsername(username string) bool {
	return len(username) >= 3 && len(username) <= 20
}

func isValidEmail(email string) bool {
	emailRegex := regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,4}$`)
	return emailRegex.MatchString(email)
}

func generateResetToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
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
		case 'A' <= char && char <= 'Z':
			hasUpper = true
		case 'a' <= char && char <= 'z':
			hasLower = true
		case '0' <= char && char <= '9':
			hasNumber = true
		case char == '!' || char == '@' || char == '#' || char == '$' || char == '%' || char == '^' || char == '&' || char == '*':
			hasSpecial = true
		}
	}

	if !hasUpper || !hasLower || !hasNumber || !hasSpecial {
		return fmt.Errorf("password must contain at least one uppercase letter, one lowercase letter, one number, and one special character (!@#$%%^&*)")
	}

	return nil
}