package user

import (
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Nero7991/devlm/devlm-identity/pkg/database"
	"github.com/Nero7991/devlm/devlm-identity/pkg/models"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

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

func (m *MockDB) GetUserByID(id int) (*models.User, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockDB) UpdateUser(user *models.User) error {
	args := m.Called(user)
	return args.Error(0)
}

func (m *MockDB) DeleteUser(id int) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *MockDB) ListUsers(limit, offset int) ([]*models.User, error) {
	args := m.Called(limit, offset)
	return args.Get(0).([]*models.User), args.Error(1)
}

func (m *MockDB) AddSSHKey(userID int, key string) error {
	args := m.Called(userID, key)
	return args.Error(0)
}

func (m *MockDB) CheckDatabaseSchema() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockDB) MigrateDatabase() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockDB) Close() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockDB) CreateUserTable() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockDB) CreateSSHKeysTable() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockDB) CreateResetTokensTable() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockDB) UpdatePassword(userID int, newPasswordHash string) error {
	args := m.Called(userID, newPasswordHash)
	return args.Error(0)
}

func (m *MockDB) ListSSHKeys(userID int) ([]string, error) {
	args := m.Called(userID)
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockDB) DeleteSSHKey(userID int, keyID int) error {
	args := m.Called(userID, keyID)
	return args.Error(0)
}

func (m *MockDB) StoreResetToken(userID int, token string, expiresAt time.Time) error {
	args := m.Called(userID, token, expiresAt)
	return args.Error(0)
}

func (m *MockDB) ValidateResetToken(token string) (int, error) {
	args := m.Called(token)
	return args.Int(0), args.Error(1)
}

func (m *MockDB) InvalidateResetToken(token string) error {
	args := m.Called(token)
	return args.Error(0)
}

func (m *MockDB) UpdateUserPassword(userID int, newPasswordHash string) error {
	args := m.Called(userID, newPasswordHash)
	return args.Error(0)
}

func (m *MockDB) Exec(query string, args ...interface{}) (database.Result, error) {
	mockArgs := m.Called(append([]interface{}{query}, args...)...)
	return mockArgs.Get(0).(database.Result), mockArgs.Error(1)
}

func (m *MockDB) QueryRow(query string, args ...interface{}) database.Row {
	mockArgs := m.Called(append([]interface{}{query}, args...)...)
	return mockArgs.Get(0).(database.Row)
}

func (m *MockDB) Query(query string, args ...interface{}) (database.Rows, error) {
	mockArgs := m.Called(append([]interface{}{query}, args...)...)
	return mockArgs.Get(0).(database.Rows), mockArgs.Error(1)
}

func (m *MockDB) GetUserByResetToken(token string) (*models.User, error) {
	args := m.Called(token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

type MockLogger struct {
	mock.Mock
}

func (m *MockLogger) Write(p []byte) (n int, err error) {
	args := m.Called(p)
	return args.Int(0), args.Error(1)
}

func NewMockLogger() *log.Logger {
	return log.New(&MockLogger{}, "", 0)
}

func TestCreateUser(t *testing.T) {
	mockDB := new(MockDB)
	mockLogger := new(MockLogger)
	logger := log.New(mockLogger, "", 0)
	service := NewService(mockDB, logger)

	user := &models.User{
		Username: "testuser",
		Email:    "testuser@example.com",
		Password: "TestPassword123!",
	}

	mockDB.On("CreateUser", mock.AnythingOfType("*models.User")).Return(nil)
	mockLogger.On("Write", mock.AnythingOfType("[]uint8")).Return(0, nil)

	reqBody, _ := json.Marshal(user)
	req, _ := http.NewRequest("POST", "/users", strings.NewReader(string(reqBody)))
	w := httptest.NewRecorder()

	service.CreateUser(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	mockDB.AssertExpectations(t)
	mockLogger.AssertExpectations(t)
}

func TestCreateUserDuplicate(t *testing.T) {
	mockDB := new(MockDB)
	mockLogger := new(MockLogger)
	logger := log.New(mockLogger, "", 0)
	service := NewService(mockDB, logger)

	user := &models.User{
		Username: "existinguser",
		Email:    "existing@example.com",
		Password: "TestPassword123!",
	}

	mockDB.On("CreateUser", mock.AnythingOfType("*models.User")).Return(database.ErrDuplicateKey)
	mockLogger.On("Write", mock.AnythingOfType("[]uint8")).Return(0, nil)

	reqBody, _ := json.Marshal(user)
	req, _ := http.NewRequest("POST", "/users", strings.NewReader(string(reqBody)))
	w := httptest.NewRecorder()

	service.CreateUser(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)
	mockDB.AssertExpectations(t)
	mockLogger.AssertExpectations(t)
}

func TestGetUserByID(t *testing.T) {
	mockDB := new(MockDB)
	mockLogger := new(MockLogger)
	logger := log.New(mockLogger, "", 0)
	service := NewService(mockDB, logger)

	expectedUser := &models.User{
		ID:       1,
		Username: "testuser",
		Email:    "testuser@example.com",
	}

	mockDB.On("GetUserByID", 1).Return(expectedUser, nil)
	mockLogger.On("Write", mock.AnythingOfType("[]uint8")).Return(0, nil)

	req, _ := http.NewRequest("GET", "/users/1", nil)
	w := httptest.NewRecorder()
	vars := map[string]string{
		"id": "1",
	}
	req = mux.SetURLVars(req, vars)

	service.GetUser(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var responseUser models.User
	json.Unmarshal(w.Body.Bytes(), &responseUser)
	assert.Equal(t, expectedUser.ID, responseUser.ID)
	assert.Equal(t, expectedUser.Username, responseUser.Username)
	assert.Equal(t, expectedUser.Email, responseUser.Email)

	mockDB.AssertExpectations(t)
	mockLogger.AssertExpectations(t)
}

func TestGetUserByIDNotFound(t *testing.T) {
	mockDB := new(MockDB)
	mockLogger := new(MockLogger)
	logger := log.New(mockLogger, "", 0)
	service := NewService(mockDB, logger)

	mockDB.On("GetUserByID", 999).Return(nil, database.ErrUserNotFound)
	mockLogger.On("Write", mock.AnythingOfType("[]uint8")).Return(0, nil)

	req, _ := http.NewRequest("GET", "/users/999", nil)
	w := httptest.NewRecorder()
	vars := map[string]string{
		"id": "999",
	}
	req = mux.SetURLVars(req, vars)

	service.GetUser(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	mockDB.AssertExpectations(t)
	mockLogger.AssertExpectations(t)
}

func TestUpdateUser(t *testing.T) {
	mockDB := new(MockDB)
	mockLogger := new(MockLogger)
	logger := log.New(mockLogger, "", 0)
	service := NewService(mockDB, logger)

	user := &models.User{
		ID:       1,
		Username: "updateduser",
		Email:    "updated@example.com",
	}

	mockDB.On("GetUserByID", 1).Return(user, nil)
	mockDB.On("UpdateUser", mock.AnythingOfType("*models.User")).Return(nil)
	mockLogger.On("Write", mock.AnythingOfType("[]uint8")).Return(0, nil)

	reqBody, _ := json.Marshal(user)
	req, _ := http.NewRequest("PUT", "/users/1", strings.NewReader(string(reqBody)))
	w := httptest.NewRecorder()
	vars := map[string]string{
		"id": "1",
	}
	req = mux.SetURLVars(req, vars)

	service.UpdateUser(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	mockDB.AssertExpectations(t)
	mockLogger.AssertExpectations(t)
}

func TestDeleteUser(t *testing.T) {
	mockDB := new(MockDB)
	mockLogger := new(MockLogger)
	logger := log.New(mockLogger, "", 0)
	service := NewService(mockDB, logger)

	mockDB.On("DeleteUser", 1).Return(nil)
	mockLogger.On("Write", mock.AnythingOfType("[]uint8")).Return(0, nil)

	req, _ := http.NewRequest("DELETE", "/users/1", nil)
	w := httptest.NewRecorder()
	vars := map[string]string{
		"id": "1",
	}
	req = mux.SetURLVars(req, vars)

	service.DeleteUser(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	mockDB.AssertExpectations(t)
	mockLogger.AssertExpectations(t)
}

func TestListUsers(t *testing.T) {
	mockDB := new(MockDB)
	mockLogger := new(MockLogger)
	logger := log.New(mockLogger, "", 0)
	service := NewService(mockDB, logger)

	expectedUsers := []*models.User{
		{ID: 1, Username: "user1", Email: "user1@example.com"},
		{ID: 2, Username: "user2", Email: "user2@example.com"},
	}

	mockDB.On("ListUsers", 10, 0).Return(expectedUsers, nil)
	mockLogger.On("Write", mock.AnythingOfType("[]uint8")).Return(0, nil)

	req, _ := http.NewRequest("GET", "/users?limit=10&offset=0", nil)
	w := httptest.NewRecorder()

	service.ListUsers(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var responseUsers []*models.User
	json.Unmarshal(w.Body.Bytes(), &responseUsers)
	assert.Equal(t, expectedUsers, responseUsers)

	mockDB.AssertExpectations(t)
	mockLogger.AssertExpectations(t)
}

func TestGetUserByUsername(t *testing.T) {
	mockDB := new(MockDB)
	mockLogger := new(MockLogger)
	logger := log.New(mockLogger, "", 0)
	service := NewService(mockDB, logger)

	expectedUser := &models.User{
		ID:       1,
		Username: "testuser",
		Email:    "testuser@example.com",
	}

	mockDB.On("GetUserByUsername", "testuser").Return(expectedUser, nil)
	mockLogger.On("Write", mock.AnythingOfType("[]uint8")).Return(0, nil)

	user, err := service.GetUserByUsername("testuser")
	assert.NoError(t, err)
	assert.Equal(t, expectedUser, user)

	mockDB.AssertExpectations(t)
	mockLogger.AssertExpectations(t)
}