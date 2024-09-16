package models

import (
	"errors"
	"fmt"
	"log"
	"time"
	"unicode"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidPassword = errors.New("invalid password")
	ErrInvalidRole     = errors.New("invalid role")
)

type User struct {
	ID           uuid.UUID  `json:"id"`
	Username     string     `json:"username"`
	Email        string     `json:"email"`
	Password     string     `json:"-"` // Password is omitted from JSON output
	PasswordHash string     `json:"-"` // PasswordHash is used for database operations
	Role         string     `json:"role"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	DeletedAt    *time.Time `json:"deleted_at,omitempty"`
	CreatorID    *uuid.UUID `json:"creator_id,omitempty"`
	ResetToken   string     `json:"-"` // ResetToken for password reset
	ResetExpiry  time.Time  `json:"-"` // ResetExpiry for password reset token
	LastLoginAt  *time.Time `json:"last_login_at,omitempty"`
}

type SSHKey struct {
	ID        uuid.UUID `json:"id"`
	UserID    uuid.UUID `json:"user_id"`
	PublicKey string    `json:"public_key"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// NewUser creates a new User instance with default values
func NewUser(username, email, password string) (*User, error) {
	log.Printf("Creating new user: username=%s, email=%s", username, email)

	if err := validatePassword(password); err != nil {
		log.Printf("Password validation failed: %v", err)
		return nil, fmt.Errorf("%w: %v", ErrInvalidPassword, err)
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Failed to hash password: %v", err)
		return nil, err
	}

	now := time.Now()
	user := &User{
		ID:           uuid.New(),
		Username:     username,
		Email:        email,
		PasswordHash: string(hashedPassword),
		Role:         "user", // Default role
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	log.Printf("User created successfully: ID=%s, Username=%s, Role=%s, CreatedAt=%s", user.ID, user.Username, user.Role, user.CreatedAt)
	return user, nil
}

// SetPassword sets the user's password
func (u *User) SetPassword(password string) error {
	log.Printf("Setting password for user: ID=%s, Username=%s", u.ID, u.Username)

	if err := validatePassword(password); err != nil {
		log.Printf("Password validation failed: %v", err)
		return fmt.Errorf("%w: %v", ErrInvalidPassword, err)
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Failed to hash password: %v", err)
		return err
	}
	u.PasswordHash = string(hashedPassword)
	u.UpdatedAt = time.Now()

	log.Printf("Password set successfully for user: ID=%s, Username=%s, UpdatedAt=%s", u.ID, u.Username, u.UpdatedAt)
	return nil
}

// UpdatePassword updates the user's password
func (u *User) UpdatePassword(newPassword string) error {
	return u.SetPassword(newPassword)
}

// VerifyPassword checks if the provided password matches the user's hashed password
func (u *User) VerifyPassword(password string) error {
	return bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password))
}

// CheckPassword checks if the provided password is correct
func (u *User) CheckPassword(password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password))
	return err == nil
}

// UpdateEmail updates the user's email
func (u *User) UpdateEmail(newEmail string) {
	log.Printf("Updating email for user: ID=%s, Username=%s, OldEmail=%s, NewEmail=%s", u.ID, u.Username, u.Email, newEmail)
	u.Email = newEmail
	u.UpdatedAt = time.Now()
	log.Printf("Email updated successfully for user: ID=%s, Username=%s, NewEmail=%s, UpdatedAt=%s", u.ID, u.Username, u.Email, u.UpdatedAt)
}

// UpdateRole updates the user's role
func (u *User) UpdateRole(newRole string) error {
	log.Printf("Updating role for user: ID=%s, Username=%s, OldRole=%s, NewRole=%s", u.ID, u.Username, u.Role, newRole)
	if !isValidRole(newRole) {
		log.Printf("Invalid role provided: %s", newRole)
		return ErrInvalidRole
	}
	u.Role = newRole
	u.UpdatedAt = time.Now()
	log.Printf("Role updated successfully for user: ID=%s, Username=%s, NewRole=%s, UpdatedAt=%s", u.ID, u.Username, u.Role, u.UpdatedAt)
	return nil
}

// SetResetToken sets the password reset token and expiry
func (u *User) SetResetToken(token string, expiry time.Time) {
	log.Printf("Setting reset token for user: ID=%s, Username=%s", u.ID, u.Username)
	u.ResetToken = token
	u.ResetExpiry = expiry
	u.UpdatedAt = time.Now()
	log.Printf("Reset token set successfully for user: ID=%s, Username=%s, TokenExpiry=%s, UpdatedAt=%s", u.ID, u.Username, u.ResetExpiry, u.UpdatedAt)
}

// ClearResetToken clears the password reset token and expiry
func (u *User) ClearResetToken() {
	log.Printf("Clearing reset token for user: ID=%s, Username=%s", u.ID, u.Username)
	u.ResetToken = ""
	u.ResetExpiry = time.Time{}
	u.UpdatedAt = time.Now()
	log.Printf("Reset token cleared successfully for user: ID=%s, Username=%s, UpdatedAt=%s", u.ID, u.Username, u.UpdatedAt)
}

// IsResetTokenValid checks if the reset token is valid and not expired
func (u *User) IsResetTokenValid() bool {
	isValid := u.ResetToken != "" && time.Now().Before(u.ResetExpiry)
	log.Printf("Checking reset token validity for user: ID=%s, Username=%s, IsValid=%v", u.ID, u.Username, isValid)
	return isValid
}

// UpdateLastLogin updates the user's last login timestamp
func (u *User) UpdateLastLogin() {
	now := time.Now()
	u.LastLoginAt = &now
	u.UpdatedAt = now
	log.Printf("Updated last login for user: ID=%s, Username=%s, LastLoginAt=%s, UpdatedAt=%s", u.ID, u.Username, u.LastLoginAt, u.UpdatedAt)
}

// SoftDelete marks the user as deleted
func (u *User) SoftDelete() {
	now := time.Now()
	u.DeletedAt = &now
	u.UpdatedAt = now
	log.Printf("Soft deleted user: ID=%s, Username=%s, DeletedAt=%s, UpdatedAt=%s", u.ID, u.Username, u.DeletedAt, u.UpdatedAt)
}

// Restore removes the soft delete mark from the user
func (u *User) Restore() {
	u.DeletedAt = nil
	u.UpdatedAt = time.Now()
	log.Printf("Restored user: ID=%s, Username=%s, UpdatedAt=%s", u.ID, u.Username, u.UpdatedAt)
}

func validatePassword(password string) error {
	log.Printf("Validating password")

	if len(password) < 8 {
		log.Printf("Password validation failed: password is too short")
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

	if !hasUpper {
		log.Printf("Password validation failed: missing uppercase letter")
		return errors.New("password must contain at least one uppercase letter")
	}
	if !hasLower {
		log.Printf("Password validation failed: missing lowercase letter")
		return errors.New("password must contain at least one lowercase letter")
	}
	if !hasNumber {
		log.Printf("Password validation failed: missing number")
		return errors.New("password must contain at least one number")
	}
	if !hasSpecial {
		log.Printf("Password validation failed: missing special character")
		return errors.New("password must contain at least one special character")
	}

	log.Printf("Password validation passed")
	return nil
}

// isValidRole checks if the provided role is valid
func isValidRole(role string) bool {
	validRoles := []string{"user", "admin", "developer", "editor", "viewer", "reviewer"}
	for _, r := range validRoles {
		if r == role {
			return true
		}
	}
	return false
}