package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/Nero7991/devlm/devlm-identity/internal/auth"
	"github.com/Nero7991/devlm/devlm-identity/pkg/database"
	"github.com/Nero7991/devlm/devlm-identity/pkg/models"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	testDB     database.PostgresDB
	testServer *httptest.Server
	testAuth   *auth.Service
)

func TestMain(m *testing.M) {
	if err := godotenv.Load("../../.env.test"); err != nil {
		if err := godotenv.Load("../../.env"); err != nil {
			log.Printf("Error loading .env file: %v", err)
		}
	}

	var err error
	testDB, err = database.NewPostgresDB()
	if err != nil {
		log.Fatalf("Failed to connect to test database: %v", err)
	}

	if err := initTestDatabaseSchema(testDB); err != nil {
		log.Fatalf("Failed to initialize test database schema: %v", err)
	}

	testAuth = auth.NewService(testDB, log.New(os.Stdout, "TEST: ", log.LstdFlags))

	router := mux.NewRouter()
	auth.RegisterRoutes(router, testAuth)
	testServer = httptest.NewServer(router)

	code := m.Run()

	testServer.Close()
	testDB.Close()

	os.Exit(code)
}

func initTestDatabaseSchema(db database.PostgresDB) error {
	if err := db.CreateUserTable(); err != nil {
		return fmt.Errorf("failed to create users table: %v", err)
	}
	if err := db.CreateSSHKeysTable(); err != nil {
		return fmt.Errorf("failed to create ssh_keys table: %v", err)
	}
	if err := db.CreateResetTokensTable(); err != nil {
		return fmt.Errorf("failed to create reset_tokens table: %v", err)
	}
	return nil
}

func TestIntegrationRegisterLogin(t *testing.T) {
	registerPayload := map[string]string{
		"username": "testuser",
		"email":    "testuser@example.com",
		"password": "Test@123",
		"role":     "user",
	}
	registerBody, _ := json.Marshal(registerPayload)
	resp, err := http.Post(testServer.URL+"/api/auth/register", "application/json", bytes.NewBuffer(registerBody))
	require.NoError(t, err)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	loginPayload := map[string]string{
		"username": "testuser",
		"password": "Test@123",
	}
	loginBody, _ := json.Marshal(loginPayload)
	resp, err = http.Post(testServer.URL+"/api/auth/login", "application/json", bytes.NewBuffer(loginBody))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var loginResponse map[string]string
	json.NewDecoder(resp.Body).Decode(&loginResponse)
	assert.Contains(t, loginResponse, "token")
	assert.Contains(t, loginResponse, "refresh_token")
}

func TestIntegrationRefreshToken(t *testing.T) {
	user := createTestUser(t)
	token, refreshToken := loginTestUser(t, user)

	refreshPayload := map[string]string{
		"refresh_token": refreshToken,
	}
	refreshBody, _ := json.Marshal(refreshPayload)
	req, _ := http.NewRequest("POST", testServer.URL+"/api/auth/refresh", bytes.NewBuffer(refreshBody))
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var refreshResponse map[string]string
	json.NewDecoder(resp.Body).Decode(&refreshResponse)
	assert.Contains(t, refreshResponse, "token")
}

func TestIntegrationChangePassword(t *testing.T) {
	user := createTestUser(t)
	token, _ := loginTestUser(t, user)

	changePasswordPayload := map[string]string{
		"old_password": "Test@123",
		"new_password": "NewTest@456",
	}
	changePasswordBody, _ := json.Marshal(changePasswordPayload)
	req, _ := http.NewRequest("POST", testServer.URL+"/api/auth/change-password", bytes.NewBuffer(changePasswordBody))
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	loginPayload := map[string]string{
		"username": user.Username,
		"password": "NewTest@456",
	}
	loginBody, _ := json.Marshal(loginPayload)
	resp, err = http.Post(testServer.URL+"/api/auth/login", "application/json", bytes.NewBuffer(loginBody))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestIntegrationForgotResetPassword(t *testing.T) {
	user := createTestUser(t)

	forgotPasswordPayload := map[string]string{
		"email": user.Email,
	}
	forgotPasswordBody, _ := json.Marshal(forgotPasswordPayload)
	resp, err := http.Post(testServer.URL+"/api/auth/forgot-password", "application/json", bytes.NewBuffer(forgotPasswordBody))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var resetToken string
	err = testDB.QueryRow("SELECT token FROM reset_tokens WHERE user_id = $1", user.ID).Scan(&resetToken)
	require.NoError(t, err)

	resetPasswordPayload := map[string]string{
		"reset_token":  resetToken,
		"new_password": "ResetTest@789",
	}
	resetPasswordBody, _ := json.Marshal(resetPasswordPayload)
	resp, err = http.Post(testServer.URL+"/api/auth/reset-password", "application/json", bytes.NewBuffer(resetPasswordBody))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	loginPayload := map[string]string{
		"username": user.Username,
		"password": "ResetTest@789",
	}
	loginBody, _ := json.Marshal(loginPayload)
	resp, err = http.Post(testServer.URL+"/api/auth/login", "application/json", bytes.NewBuffer(loginBody))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestIntegrationRateLimiting(t *testing.T) {
	loginPayload := map[string]string{
		"username": "nonexistent",
		"password": "wrongpassword",
	}
	loginBody, _ := json.Marshal(loginPayload)

	for i := 0; i < 6; i++ {
		resp, err := http.Post(testServer.URL+"/api/auth/login", "application/json", bytes.NewBuffer(loginBody))
		require.NoError(t, err)
		if i < 5 {
			assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		} else {
			assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
		}
	}

	time.Sleep(1 * time.Minute)

	resp, err := http.Post(testServer.URL+"/api/auth/login", "application/json", bytes.NewBuffer(loginBody))
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestIntegrationRegisterDuplicateUser(t *testing.T) {
	user := createTestUser(t)

	registerPayload := map[string]string{
		"username": user.Username,
		"email":    user.Email,
		"password": "Test@123",
		"role":     "user",
	}
	registerBody, _ := json.Marshal(registerPayload)
	resp, err := http.Post(testServer.URL+"/api/auth/register", "application/json", bytes.NewBuffer(registerBody))
	require.NoError(t, err)
	assert.Equal(t, http.StatusConflict, resp.StatusCode)

	var response map[string]string
	json.NewDecoder(resp.Body).Decode(&response)
	assert.Contains(t, response["error"], "already exists")
}

func TestIntegrationInvalidTokenRefresh(t *testing.T) {
	refreshPayload := map[string]string{
		"refresh_token": "invalid_refresh_token",
	}
	refreshBody, _ := json.Marshal(refreshPayload)
	req, _ := http.NewRequest("POST", testServer.URL+"/api/auth/refresh", bytes.NewBuffer(refreshBody))
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestIntegrationWeakPasswordReset(t *testing.T) {
	user := createTestUser(t)

	var resetToken string
	err := testDB.QueryRow("SELECT token FROM reset_tokens WHERE user_id = $1", user.ID).Scan(&resetToken)
	require.NoError(t, err)

	resetPasswordPayload := map[string]string{
		"reset_token":  resetToken,
		"new_password": "weak",
	}
	resetPasswordBody, _ := json.Marshal(resetPasswordPayload)
	resp, err := http.Post(testServer.URL+"/api/auth/reset-password", "application/json", bytes.NewBuffer(resetPasswordBody))
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var response map[string]string
	json.NewDecoder(resp.Body).Decode(&response)
	assert.Contains(t, response["error"], "password must be at least")
}

func createTestUser(t *testing.T) *models.User {
	username := fmt.Sprintf("testuser%d", time.Now().UnixNano())
	email := fmt.Sprintf("%s@example.com", username)
	user := &models.User{
		Username: username,
		Email:    email,
		Role:     "user",
	}
	err := user.SetPassword("Test@123")
	require.NoError(t, err)
	err = testDB.CreateUser(user)
	require.NoError(t, err)
	return user
}

func loginTestUser(t *testing.T, user *models.User) (string, string) {
	loginPayload := map[string]string{
		"username": user.Username,
		"password": "Test@123",
	}
	loginBody, _ := json.Marshal(loginPayload)
	resp, err := http.Post(testServer.URL+"/api/auth/login", "application/json", bytes.NewBuffer(loginBody))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var loginResponse map[string]string
	json.NewDecoder(resp.Body).Decode(&loginResponse)
	return loginResponse["token"], loginResponse["refresh_token"]
}

func TestIntegrationLogout(t *testing.T) {
	user := createTestUser(t)
	token, _ := loginTestUser(t, user)

	req, _ := http.NewRequest("POST", testServer.URL+"/api/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var response map[string]string
	json.NewDecoder(resp.Body).Decode(&response)
	assert.Contains(t, response["message"], "Logged out successfully")
}

func TestIntegrationUpdateUserRole(t *testing.T) {
	adminUser := createTestUser(t)
	adminUser.Role = "admin"
	err := testDB.UpdateUser(adminUser)
	require.NoError(t, err)

	token, _ := loginTestUser(t, adminUser)

	regularUser := createTestUser(t)

	updateRolePayload := map[string]string{
		"role": "moderator",
	}
	updateRoleBody, _ := json.Marshal(updateRolePayload)
	req, _ := http.NewRequest("PATCH", fmt.Sprintf("%s/api/users/%d/update-role", testServer.URL, regularUser.ID), bytes.NewBuffer(updateRoleBody))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	updatedUser, err := testDB.GetUserByID(regularUser.ID)
	require.NoError(t, err)
	assert.Equal(t, "moderator", updatedUser.Role)
}

func TestIntegrationGetUser(t *testing.T) {
	user := createTestUser(t)
	token, _ := loginTestUser(t, user)

	req, _ := http.NewRequest("GET", fmt.Sprintf("%s/api/users/%d", testServer.URL, user.ID), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var fetchedUser models.User
	json.NewDecoder(resp.Body).Decode(&fetchedUser)
	assert.Equal(t, user.ID, fetchedUser.ID)
	assert.Equal(t, user.Username, fetchedUser.Username)
	assert.Equal(t, user.Email, fetchedUser.Email)
	assert.Equal(t, user.Role, fetchedUser.Role)
	assert.Empty(t, fetchedUser.PasswordHash)
}

func TestIntegrationListUsers(t *testing.T) {
	adminUser := createTestUser(t)
	adminUser.Role = "admin"
	err := testDB.UpdateUser(adminUser)
	require.NoError(t, err)

	token, _ := loginTestUser(t, adminUser)

	for i := 0; i < 5; i++ {
		createTestUser(t)
	}

	req, _ := http.NewRequest("GET", testServer.URL+"/api/users?limit=10&offset=0", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var users []models.User
	json.NewDecoder(resp.Body).Decode(&users)
	assert.GreaterOrEqual(t, len(users), 6)
	for _, user := range users {
		assert.Empty(t, user.PasswordHash)
	}
}