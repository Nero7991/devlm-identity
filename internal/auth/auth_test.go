package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/Nero7991/devlm/devlm-identity/pkg/database"
	"github.com/Nero7991/devlm/devlm-identity/pkg/models"
	"github.com/Nero7991/devlm/devlm-identity/internal/user"
	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
)

// MockDB is a mock implementation of the database.PostgresDB interface
type MockDB struct {
	mock.Mock
}

func (m *MockDB) GetUserByUsername(username string) (*models.User, error) {
	args := m.Called(username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockDB) GetUserByEmail(email string) (*models.User, error) {
	args := m.Called(email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockDB) CreateUser(user *models.User) error {
	args := m.Called(user)
	return args.Error(0)
}

func (m *MockDB) UpdateUser(user *models.User) error {
	args := m.Called(user)
	return args.Error(0)
}

func (m *MockDB) GetUserByID(id int) (*models.User, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockDB) UpdateUserPassword(userID int, newPassword string) error {
	args := m.Called(userID, newPassword)
	return args.Error(0)
}

func (m *MockDB) GetUserByResetToken(token string) (*models.User, error) {
	args := m.Called(token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockDB) AddSSHKey(userID int, publicKey string) error {
	args := m.Called(userID, publicKey)
	return args.Error(0)
}

func (m *MockDB) Close() error {
	return nil
}

func (m *MockDB) CreateUserTable() error {
	return nil
}

func (m *MockDB) CreateSSHKeysTable() error {
	return nil
}

func (m *MockDB) CreateResetTokensTable() error {
	return nil
}

func (m *MockDB) ListUsers(limit, offset int) ([]*models.User, error) {
	return nil, nil
}

func (m *MockDB) DeleteUser(id int) error {
	return nil
}

func (m *MockDB) UpdatePassword(userID int, newPasswordHash string) error {
	return nil
}

func (m *MockDB) ListSSHKeys(userID int) ([]string, error) {
	return nil, nil
}

func (m *MockDB) DeleteSSHKey(userID int, keyID int) error {
	return nil
}

func (m *MockDB) StoreResetToken(userID int, token string, expiresAt time.Time) error {
	return nil
}

func (m *MockDB) ValidateResetToken(token string) (int, error) {
	return 0, nil
}

func (m *MockDB) InvalidateResetToken(token string) error {
	return nil
}

func (m *MockDB) Exec(query string, args ...interface{}) (database.Result, error) {
	return nil, nil
}

func (m *MockDB) QueryRow(query string, args ...interface{}) database.Row {
	return nil
}

func (m *MockDB) Query(query string, args ...interface{}) (database.Rows, error) {
	return nil, nil
}

func (m *MockDB) CheckDatabaseSchema() error {
	return nil
}

func (m *MockDB) MigrateDatabase() error {
	return nil
}

func TestLogin(t *testing.T) {
	mockDB := new(MockDB)
	mockUserService := new(user.MockUserService)
	service := NewService(mockDB, nil, mockUserService)

	t.Run("Successful login", func(t *testing.T) {
		password := "Password123!"
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		user := &models.User{
			ID:           1,
			Username:     "testuser",
			PasswordHash: string(hashedPassword),
			Role:         "user",
		}

		mockUserService.On("GetUserByUsername", "testuser").Return(user, nil)

		reqBody := []byte(`{"username": "testuser", "password": "Password123!"}`)
		req, _ := http.NewRequest("POST", "/auth/login", bytes.NewBuffer(reqBody))
		rr := httptest.NewRecorder()

		handler := http.HandlerFunc(service.Login)
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var response map[string]string
		json.Unmarshal(rr.Body.Bytes(), &response)

		assert.Contains(t, response, "token")
		assert.Contains(t, response, "refresh_token")
	})

	t.Run("Invalid credentials", func(t *testing.T) {
		mockUserService.On("GetUserByUsername", "wronguser").Return(nil, database.ErrUserNotFound)

		reqBody := []byte(`{"username": "wronguser", "password": "WrongPassword123!"}`)
		req, _ := http.NewRequest("POST", "/auth/login", bytes.NewBuffer(reqBody))
		rr := httptest.NewRecorder()

		handler := http.HandlerFunc(service.Login)
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		assert.Contains(t, rr.Body.String(), "Invalid credentials")
	})

	t.Run("Malformed JSON in request body", func(t *testing.T) {
		reqBody := []byte(`{"username": "testuser", "password": "Password123!`)
		req, _ := http.NewRequest("POST", "/auth/login", bytes.NewBuffer(reqBody))
		rr := httptest.NewRecorder()

		handler := http.HandlerFunc(service.Login)
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Body.String(), "Invalid request body")
	})

	t.Run("User not found", func(t *testing.T) {
		mockUserService.On("GetUserByUsername", "nonexistentuser").Return(nil, database.ErrUserNotFound)

		reqBody := []byte(`{"username": "nonexistentuser", "password": "Password123!"}`)
		req, _ := http.NewRequest("POST", "/auth/login", bytes.NewBuffer(reqBody))
		rr := httptest.NewRecorder()

		handler := http.HandlerFunc(service.Login)
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		assert.Contains(t, rr.Body.String(), "Invalid credentials")
	})

	t.Run("Database error", func(t *testing.T) {
		mockUserService.On("GetUserByUsername", "dberroruser").Return(nil, assert.AnError)

		reqBody := []byte(`{"username": "dberroruser", "password": "Password123!"}`)
		req, _ := http.NewRequest("POST", "/auth/login", bytes.NewBuffer(reqBody))
		rr := httptest.NewRecorder()

		handler := http.HandlerFunc(service.Login)
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusInternalServerError, rr.Code)
		assert.Contains(t, rr.Body.String(), "Internal server error")
	})
}

func TestRegister(t *testing.T) {
	mockDB := new(MockDB)
	mockUserService := new(user.MockUserService)
	service := NewService(mockDB, nil, mockUserService)

	t.Run("Successful registration", func(t *testing.T) {
		mockDB.On("CreateUser", mock.AnythingOfType("*models.User")).Return(nil).Once()

		reqBody := []byte(`{"username": "newuser", "email": "newuser@example.com", "password": "Password123!"}`)
		req, _ := http.NewRequest("POST", "/auth/register", bytes.NewBuffer(reqBody))
		rr := httptest.NewRecorder()

		handler := http.HandlerFunc(service.Register)
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusCreated, rr.Code)

		var response map[string]string
		json.Unmarshal(rr.Body.Bytes(), &response)

		assert.Equal(t, "User created successfully", response["message"])
	})

	t.Run("Registration with weak password", func(t *testing.T) {
		reqBody := []byte(`{"username": "newuser", "email": "newuser@example.com", "password": "weak"}`)
		req, _ := http.NewRequest("POST", "/auth/register", bytes.NewBuffer(reqBody))
		rr := httptest.NewRecorder()

		handler := http.HandlerFunc(service.Register)
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Body.String(), "password must be at least 8 characters long")
	})

	t.Run("Registration with duplicate username", func(t *testing.T) {
		mockDB.On("CreateUser", mock.AnythingOfType("*models.User")).Return(database.ErrDuplicateKey).Once()

		reqBody := []byte(`{"username": "existinguser", "email": "newuser@example.com", "password": "Password123!"}`)
		req, _ := http.NewRequest("POST", "/auth/register", bytes.NewBuffer(reqBody))
		rr := httptest.NewRecorder()

		handler := http.HandlerFunc(service.Register)
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusConflict, rr.Code)
		assert.Contains(t, rr.Body.String(), "Username or email already exists")
	})

	t.Run("Malformed JSON in request body", func(t *testing.T) {
		reqBody := []byte(`{"username": "newuser", "email": "newuser@example.com", "password": "Password123!`)
		req, _ := http.NewRequest("POST", "/auth/register", bytes.NewBuffer(reqBody))
		rr := httptest.NewRecorder()

		handler := http.HandlerFunc(service.Register)
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Body.String(), "Invalid request body")
	})
}

func TestRefreshToken(t *testing.T) {
	mockDB := new(MockDB)
	mockUserService := new(user.MockUserService)
	service := NewService(mockDB, nil, mockUserService)

	t.Run("Successful token refresh", func(t *testing.T) {
		user := &models.User{
			ID:       1,
			Username: "testuser",
			Role:     "user",
		}

		mockDB.On("GetUserByID", 1).Return(user, nil)

		// Generate a valid refresh token
		refreshToken, _ := generateRefreshToken(user)

		reqBody := []byte(`{"refresh_token": "` + refreshToken + `"}`)
		req, _ := http.NewRequest("POST", "/auth/refresh", bytes.NewBuffer(reqBody))
		rr := httptest.NewRecorder()

		handler := http.HandlerFunc(service.RefreshToken)
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var response map[string]string
		json.Unmarshal(rr.Body.Bytes(), &response)

		assert.Contains(t, response, "token")
	})

	t.Run("Invalid refresh token", func(t *testing.T) {
		reqBody := []byte(`{"refresh_token": "invalid_refresh_token"}`)
		req, _ := http.NewRequest("POST", "/auth/refresh", bytes.NewBuffer(reqBody))
		rr := httptest.NewRecorder()

		handler := http.HandlerFunc(service.RefreshToken)
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		assert.Contains(t, rr.Body.String(), "Invalid refresh token")
	})

	t.Run("Malformed JSON in request body", func(t *testing.T) {
		reqBody := []byte(`{"refresh_token": "invalid_refresh_token`)
		req, _ := http.NewRequest("POST", "/auth/refresh", bytes.NewBuffer(reqBody))
		rr := httptest.NewRecorder()

		handler := http.HandlerFunc(service.RefreshToken)
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Body.String(), "Invalid request body")
	})
}

func TestChangePassword(t *testing.T) {
	mockDB := new(MockDB)
	mockUserService := new(user.MockUserService)
	service := NewService(mockDB, nil, mockUserService)

	t.Run("Successful password change", func(t *testing.T) {
		oldPassword := "OldPassword123!"
		hashedOldPassword, _ := bcrypt.GenerateFromPassword([]byte(oldPassword), bcrypt.DefaultCost)

		user := &models.User{
			ID:           1,
			Username:     "testuser",
			PasswordHash: string(hashedOldPassword),
		}

		mockDB.On("GetUserByID", 1).Return(user, nil)
		mockDB.On("UpdateUserPassword", 1, mock.AnythingOfType("string")).Return(nil)

		reqBody := []byte(`{"old_password": "OldPassword123!", "new_password": "NewPassword123!"}`)
		req, _ := http.NewRequest("POST", "/auth/change-password", bytes.NewBuffer(reqBody))
		req = req.WithContext(context.WithValue(req.Context(), "claims", &jwt.MapClaims{"user_id": float64(1)}))
		rr := httptest.NewRecorder()

		handler := http.HandlerFunc(service.ChangePassword)
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var response map[string]string
		json.Unmarshal(rr.Body.Bytes(), &response)

		assert.Equal(t, "Password changed successfully", response["message"])
	})

	t.Run("Invalid old password", func(t *testing.T) {
		oldPassword := "OldPassword123!"
		hashedOldPassword, _ := bcrypt.GenerateFromPassword([]byte(oldPassword), bcrypt.DefaultCost)

		user := &models.User{
			ID:           1,
			Username:     "testuser",
			PasswordHash: string(hashedOldPassword),
		}

		mockDB.On("GetUserByID", 1).Return(user, nil)

		reqBody := []byte(`{"old_password": "WrongOldPassword123!", "new_password": "NewPassword123!"}`)
		req, _ := http.NewRequest("POST", "/auth/change-password", bytes.NewBuffer(reqBody))
		req = req.WithContext(context.WithValue(req.Context(), "claims", &jwt.MapClaims{"user_id": float64(1)}))
		rr := httptest.NewRecorder()

		handler := http.HandlerFunc(service.ChangePassword)
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		assert.Contains(t, rr.Body.String(), "Invalid old password")
	})

	t.Run("Malformed JSON in request body", func(t *testing.T) {
		reqBody := []byte(`{"old_password": "OldPassword123!", "new_password": "NewPassword123!`)
		req, _ := http.NewRequest("POST", "/auth/change-password", bytes.NewBuffer(reqBody))
		req = req.WithContext(context.WithValue(req.Context(), "claims", &jwt.MapClaims{"user_id": float64(1)}))
		rr := httptest.NewRecorder()

		handler := http.HandlerFunc(service.ChangePassword)
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Body.String(), "Invalid request body")
	})
}

func TestForgotPassword(t *testing.T) {
	mockDB := new(MockDB)
	mockUserService := new(user.MockUserService)
	service := NewService(mockDB, nil, mockUserService)

	t.Run("Successful forgot password request", func(t *testing.T) {
		user := &models.User{
			ID:    1,
			Email: "test@example.com",
		}

		mockUserService.On("GetUserByEmail", "test@example.com").Return(user, nil)
		mockDB.On("UpdateUser", mock.AnythingOfType("*models.User")).Return(nil)

		reqBody := []byte(`{"email": "test@example.com"}`)
		req, _ := http.NewRequest("POST", "/auth/forgot-password", bytes.NewBuffer(reqBody))
		rr := httptest.NewRecorder()

		handler := http.HandlerFunc(service.ForgotPassword)
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var response map[string]string
		json.Unmarshal(rr.Body.Bytes(), &response)

		assert.Equal(t, "If the email is registered, a password reset link will be sent.", response["message"])
	})

	t.Run("Forgot password for non-existent user", func(t *testing.T) {
		mockUserService.On("GetUserByEmail", "nonexistent@example.com").Return(nil, database.ErrUserNotFound)

		reqBody := []byte(`{"email": "nonexistent@example.com"}`)
		req, _ := http.NewRequest("POST", "/auth/forgot-password", bytes.NewBuffer(reqBody))
		rr := httptest.NewRecorder()

		handler := http.HandlerFunc(service.ForgotPassword)
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var response map[string]string
		json.Unmarshal(rr.Body.Bytes(), &response)

		assert.Equal(t, "If the email is registered, a password reset link will be sent.", response["message"])
	})

	t.Run("Malformed JSON in request body", func(t *testing.T) {
		reqBody := []byte(`{"email": "test@example.com`)
		req, _ := http.NewRequest("POST", "/auth/forgot-password", bytes.NewBuffer(reqBody))
		rr := httptest.NewRecorder()

		handler := http.HandlerFunc(service.ForgotPassword)
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Body.String(), "Invalid request body")
	})
}

func TestResetPassword(t *testing.T) {
	mockDB := new(MockDB)
	mockUserService := new(user.MockUserService)
	service := NewService(mockDB, nil, mockUserService)

	t.Run("Successful password reset", func(t *testing.T) {
		user := &models.User{ID: 1}
		mockDB.On("GetUserByResetToken", "valid_token").Return(user, nil)
		mockDB.On("UpdateUserPassword", 1, mock.AnythingOfType("string")).Return(nil)

		reqBody := []byte(`{"reset_token": "valid_token", "new_password": "NewPassword123!"}`)
		req, _ := http.NewRequest("POST", "/auth/reset-password", bytes.NewBuffer(reqBody))
		rr := httptest.NewRecorder()

		handler := http.HandlerFunc(service.ResetPassword)
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var response map[string]string
		json.Unmarshal(rr.Body.Bytes(), &response)

		assert.Equal(t, "Password reset successfully", response["message"])
	})

	t.Run("Invalid reset token", func(t *testing.T) {
		mockDB.On("GetUserByResetToken", "invalid_token").Return(nil, database.ErrUserNotFound)

		reqBody := []byte(`{"reset_token": "invalid_token", "new_password": "NewPassword123!"}`)
		req, _ := http.NewRequest("POST", "/auth/reset-password", bytes.NewBuffer(reqBody))
		rr := httptest.NewRecorder()

		handler := http.HandlerFunc(service.ResetPassword)
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Body.String(), "Invalid or expired reset token")
	})

	t.Run("Weak new password", func(t *testing.T) {
		user := &models.User{ID: 1}
		mockDB.On("GetUserByResetToken", "valid_token").Return(user, nil)

		reqBody := []byte(`{"reset_token": "valid_token", "new_password": "weak"}`)
		req, _ := http.NewRequest("POST", "/auth/reset-password", bytes.NewBuffer(reqBody))
		rr := httptest.NewRecorder()

		handler := http.HandlerFunc(service.ResetPassword)
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Body.String(), "password must be at least 8 characters long")
	})

	t.Run("Malformed JSON in request body", func(t *testing.T) {
		reqBody := []byte(`{"reset_token": "valid_token", "new_password": "NewPassword123!`)
		req, _ := http.NewRequest("POST", "/auth/reset-password", bytes.NewBuffer(reqBody))
		rr := httptest.NewRecorder()

		handler := http.HandlerFunc(service.ResetPassword)
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Body.String(), "Invalid request body")
	})
}

func TestAuthMiddleware(t *testing.T) {
	mockDB := new(MockDB)
	mockUserService := new(user.MockUserService)
	service := NewService(mockDB, nil, mockUserService)

	t.Run("Valid token", func(t *testing.T) {
		user := &models.User{ID: 1, Username: "testuser", Role: "user"}
		token, _ := generateToken(user)

		req, _ := http.NewRequest("GET", "/protected", nil)
		req.Header.Set("Authorization", token)
		rr := httptest.NewRecorder()

		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		handler := service.AuthMiddleware(nextHandler)
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Missing token", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/protected", nil)
		rr := httptest.NewRecorder()

		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		handler := service.AuthMiddleware(nextHandler)
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		assert.Contains(t, rr.Body.String(), "Missing authorization token")
	})

	t.Run("Invalid token", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/protected", nil)
		req.Header.Set("Authorization", "invalid_token")
		rr := httptest.NewRecorder()

		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		handler := service.AuthMiddleware(nextHandler)
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		assert.Contains(t, rr.Body.String(), "Invalid token")
	})
}

func TestTokenGeneration(t *testing.T) {
	user := &models.User{
		ID:       1,
		Username: "testuser",
		Role:     "user",
	}

	t.Run("Generate access token", func(t *testing.T) {
		token, err := generateToken(user)
		assert.NoError(t, err)
		assert.NotEmpty(t, token)

		claims, err := ValidateToken(token)
		assert.NoError(t, err)
		assert.Equal(t, float64(user.ID), (*claims)["user_id"])
		assert.Equal(t, user.Username, (*claims)["username"])
		assert.Equal(t, user.Role, (*claims)["role"])
	})

	t.Run("Generate refresh token", func(t *testing.T) {
		token, err := generateRefreshToken(user)
		assert.NoError(t, err)
		assert.NotEmpty(t, token)

		claims, err := ValidateRefreshToken(token)
		assert.NoError(t, err)
		assert.Equal(t, float64(user.ID), (*claims)["user_id"])
	})
}

func TestTokenValidation(t *testing.T) {
	user := &models.User{
		ID:       1,
		Username: "testuser",
		Role:     "user",
	}

	t.Run("Validate access token", func(t *testing.T) {
		token, _ := generateToken(user)
		claims, err := ValidateToken(token)
		assert.NoError(t, err)
		assert.NotNil(t, claims)
	})

	t.Run("Validate refresh token", func(t *testing.T) {
		token, _ := generateRefreshToken(user)
		claims, err := ValidateRefreshToken(token)
		assert.NoError(t, err)
		assert.NotNil(t, claims)
	})

	t.Run("Validate expired token", func(t *testing.T) {
		expiredToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"user_id":  user.ID,
			"username": user.Username,
			"role":     user.Role,
			"exp":      time.Now().Add(-time.Hour).Unix(),
		})
		tokenString, _ := expiredToken.SignedString([]byte(getSecretKey()))

		_, err := ValidateToken(tokenString)
		assert.Error(t, err)
	})
}

func TestPasswordValidation(t *testing.T) {
	t.Run("Valid password", func(t *testing.T) {
		err := validatePassword("StrongPass123!")
		assert.NoError(t, err)
	})

	t.Run("Short password", func(t *testing.T) {
		err := validatePassword("Short1!")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "password must be at least 8 characters long")
	})

	t.Run("Password without uppercase", func(t *testing.T) {
		err := validatePassword("weakpass123!")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "password must contain at least one uppercase letter")
	})

	t.Run("Password without lowercase", func(t *testing.T) {
		err := validatePassword("STRONGPASS123!")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "password must contain at least one lowercase letter")
	})

	t.Run("Password without number", func(t *testing.T) {
		err := validatePassword("StrongPass!")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "password must contain at least one number")
	})

	t.Run("Password without special character", func(t *testing.T) {
		err := validatePassword("StrongPass123")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "password must contain at least one special character")
	})
}

func TestRateLimitMiddleware(t *testing.T) {
	mockDB := new(MockDB)
	mockUserService := new(user.MockUserService)
	service := NewService(mockDB, nil, mockUserService)

	t.Run("Rate limit not exceeded", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "/auth/login", nil)
		rr := httptest.NewRecorder()

		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		handler := RateLimitMiddleware(service.loginLimiter, nextHandler)

		for i := 0; i < 5; i++ {
			handler.ServeHTTP(rr, req)
			assert.Equal(t, http.StatusOK, rr.Code)
		}
	})

	t.Run("Rate limit exceeded", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "/auth/login", nil)
		rr := httptest.NewRecorder()

		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		handler := RateLimitMiddleware(service.loginLimiter, nextHandler)

		for i := 0; i < 6; i++ {
			handler.ServeHTTP(rr, req)
		}

		assert.Equal(t, http.StatusTooManyRequests, rr.Code)
		assert.Containst, rr.Body.String(), "Too many requests")
	})
}

func init() {
	// Set environment variables for testing
	os.Setenv("JWT_SECRET_KEY", "test-secret-key")
	os.Setenv("JWT_REFRESH_SECRET_KEY", "test-refresh-secret-key")
}

func TestRateLimitMiddlewareForRegister(t *testing.T) {
	mockDB := new(MockDB)
	mockUserService := new(user.MockUserService)
	service := NewService(mockDB, nil, mockUserService)

	t.Run("Register rate limit not exceeded", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "/auth/register", nil)
		rr := httptest.NewRecorder()

		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		handler := RateLimitMiddleware(service.registerLimiter, nextHandler)

		for i := 0; i < 10; i++ {
			handler.ServeHTTP(rr, req)
			assert.Equal(t, http.StatusOK, rr.Code)
		}
	})

	t.Run("Register rate limit exceeded", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "/auth/register", nil)
		rr := httptest.NewRecorder()

		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		handler := RateLimitMiddleware(service.registerLimiter, nextHandler)

		for i := 0; i < 11; i++ {
			handler.ServeHTTP(rr, req)
		}

		assert.Equal(t, http.StatusTooManyRequests, rr.Code)
		assert.Contains(t, rr.Body.String(), "Too many requests")
	})
}

func TestRateLimitMiddlewareForResetPassword(t *testing.T) {
	mockDB := new(MockDB)
	mockUserService := new(user.MockUserService)
	service := NewService(mockDB, nil, mockUserService)

	t.Run("Reset password rate limit not exceeded", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "/auth/reset-password", nil)
		rr := httptest.NewRecorder()

		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		handler := RateLimitMiddleware(service.resetPasswordLimiter, nextHandler)

		for i := 0; i < 3; i++ {
			handler.ServeHTTP(rr, req)
			assert.Equal(t, http.StatusOK, rr.Code)
		}
	})

	t.Run("Reset password rate limit exceeded", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "/auth/reset-password", nil)
		rr := httptest.NewRecorder()

		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		handler := RateLimitMiddleware(service.resetPasswordLimiter, nextHandler)

		for i := 0; i < 4; i++ {
			handler.ServeHTTP(rr, req)
		}

		assert.Equal(t, http.StatusTooManyRequests, rr.Code)
		assert.Contains(t, rr.Body.String(), "Too many requests")
	})
}