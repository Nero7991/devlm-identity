package ssh

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/Nero7991/devlm/devlm-identity/pkg/models"
	"github.com/Nero7991/devlm/devlm-identity/pkg/database"
)

type mockPostgresDB struct {
	db   *sql.DB
	mock sqlmock.Sqlmock
}

func (m *mockPostgresDB) Close() error {
	return m.db.Close()
}

func (m *mockPostgresDB) CreateUserTable() error {
	return nil
}

func (m *mockPostgresDB) CreateSSHKeysTable() error {
	return nil
}

func (m *mockPostgresDB) CreateResetTokensTable() error {
	return nil
}

func (m *mockPostgresDB) ListUsers(limit, offset int) ([]*models.User, error) {
	return nil, nil
}

func (m *mockPostgresDB) UpdateUser(user *models.User) error {
	return nil
}

func (m *mockPostgresDB) DeleteUser(id int) error {
	return nil
}

func (m *mockPostgresDB) GetUserByID(id int) (*models.User, error) {
	return nil, nil
}

func (m *mockPostgresDB) GetUserByUsername(username string) (*models.User, error) {
	return nil, nil
}

func (m *mockPostgresDB) CreateUser(user *models.User) error {
	return nil
}

func (m *mockPostgresDB) GetUserByEmail(email string) (*models.User, error) {
	return nil, nil
}

func (m *mockPostgresDB) UpdatePassword(userID int, newPasswordHash string) error {
	return nil
}

func (m *mockPostgresDB) AddSSHKey(userID int, publicKey string) error {
	_, err := m.db.Exec("INSERT INTO ssh_keys (user_id, public_key) VALUES (?, ?)", userID, publicKey)
	return err
}

func (m *mockPostgresDB) ListSSHKeys(userID int) ([]string, error) {
	rows, err := m.db.Query("SELECT public_key FROM ssh_keys WHERE user_id = ?", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []string
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func (m *mockPostgresDB) DeleteSSHKey(userID int, keyID int) error {
	_, err := m.db.Exec("DELETE FROM ssh_keys WHERE id = ? AND user_id = ?", keyID, userID)
	return err
}

func (m *mockPostgresDB) StoreResetToken(userID int, token string, expiresAt time.Time) error {
	return nil
}

func (m *mockPostgresDB) ValidateResetToken(token string) (int, error) {
	return 0, nil
}

func (m *mockPostgresDB) InvalidateResetToken(token string) error {
	return nilगुरु 
}

func (m *mockPostgresDB) UpdateUserPassword(userID int, newPasswordHash string) error {
	return nil
}

func (m *mockPostgresDB) Exec(query string, args ...interface{}) (database.Result, error) {
	return m.db.Exec(query, args...)
}

func (m *mockPostgresDB) QueryRow(query string, args ...interface{}) database.Row {
	return m.db.QueryRow(query, args...)
}

func (m *mockPostgresDB) Query(query string, args ...interface{}) (database.Rows, error) {
	return m.db.Query(query, args...)
}

func (m *mockPostgresDB) GetUserByResetToken(token string) (*models.User, error) {
	return nil, nil
}

func (m *mockPostgresDB) CheckDatabaseSchema() error {
	return nil
}

func (m *mockPostgresDB) MigrateDatabase() error {
	return nil
}

func TestGenerateSSHKey(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}
	defer db.Close()

	service := NewService(&mockPostgresDB{db: db, mock: mock})

	mock.ExpectExec("INSERT INTO ssh_keys").WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(1, 1))

	privateKey, publicKey, err := service.GenerateSSHKey(1)

	assert.NoError(t, err)
	assert.NotEmpty(t, privateKey)
	assert.NotEmpty(t, publicKey)
	assert.Contains(t, privateKey, "RSA PRIVATE KEY")
	assert.Contains(t, publicKey, "ssh-rsa")

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %s", err)
	}
}

func TestGetSSHKey(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}
	defer db.Close()

	service := NewService(&mockPostgresDB{db: db, mock: mock})

	expectedPublicKey := "ssh-rsa AAAAB3NzaC1yc2E..."
	rows := sqlmock.NewRows([]string{"public_key"}).AddRow(expectedPublicKey)
	mock.ExpectQuery("SELECT public_key FROM ssh_keys").WithArgs(1).WillReturnRows(rows)

	publicKey, err := service.GetSSHKey(1)

	assert.NoError(t, err)
	assert.Equal(t, expectedPublicKey, publicKey)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %s", err)
	}
}

func TestDeleteSSHKeyHandler(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}
	defer db.Close()

	service := NewService(&mockPostgresDB{db: db, mock: mock})

	mock.ExpectExec("DELETE FROM ssh_keys").WithArgs(1, 1).WillReturnResult(sqlmock.NewResult(1, 1))

	req, _ := http.NewRequest("DELETE", "/ssh/keys/1", nil)
	req = req.WithContext(context.WithValue(req.Context(), "user_id", "1"))
	vars := map[string]string{
		"id": "1",
	}
	req = mux.SetURLVars(req, vars)
	w := httptest.NewRecorder()

	service.DeleteSSHKeyHandler(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %s", err)
	}
}

func TestListSSHKeysHandler(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}
	defer db.Close()

	service := NewService(&mockPostgresDB{db: db, mock: mock})

	expectedKeys := []string{"ssh-rsa AAAAB3NzaC1yc2E..."}

	rows := sqlmock.NewRows([]string{"public_key"}).
		AddRow("ssh-rsa AAAAB3NzaC1yc2E...")

	mock.ExpectQuery("SELECT public_key FROM ssh_keys").WithArgs(1).WillReturnRows(rows)

	req, _ := http.NewRequest("GET", "/ssh/keys", nil)
	req = req.WithContext(context.WithValue(req.Context(), "user_id", "1"))
	w := httptest.NewRecorder()

	service.ListSSHKeysHandler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response []map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(response))
	assert.Equal(t, float64(1), response[0]["id"])
	assert.Equal(t, expectedKeys[0], response[0]["public_key"])

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %s", err)
	}
}

func TestAddSSHKeyHandler(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}
	defer db.Close()

	service := NewService(&mockPostgresDB{db: db, mock: mock})

	mock.ExpectExec("INSERT INTO ssh_keys").WithArgs(1, "ssh-rsa AAAAB3NzaC1yc2E...").WillReturnResult(sqlmock.NewResult(1, 1))

	reqBody := `{"public_key": "ssh-rsa AAAAB3NzaC1yc2E..."}`
	req, _ := http.NewRequest("POST", "/ssh/keys", strings.NewReader(reqBody))
	req = req.WithContext(context.WithValue(req.Context(), "user_id", "1"))
	w := httptest.NewRecorder()

	service.AddSSHKeyHandler(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %s", err)
	}
}

func TestRegisterRoutes(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}
	defer db.Close()

	service := NewService(&mockPostgresDB{db: db})

	router := mux.NewRouter()
	RegisterRoutes(router, service)

	routes := []struct {
		Method string
		Path   string
	}{
		{"GET", "/keys"},
		{"POST", "/keys"},
		{"DELETE", "/keys/{id:[0-9]+}"},
	}

	for _, route := range routes {
		found := false
		err := router.Walk(func(r *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
			pathTemplate, _ := r.GetPathTemplate()
			methods, _ := r.GetMethods()
			if pathTemplate == route.Path && len(methods) > 0 && methods[0] == route.Method {
				found = true
			}
			return nil
		})
		assert.NoError(t, err)
		assert.True(t, found, fmt.Sprintf("Route %s %s not found", route.Method, route.Path))
	}
}

func TestGetUserIDFromRequest(t *testing.T) {
	req, _ := http.NewRequest("GET", "/", nil)
	req = req.WithContext(context.WithValue(req.Context(), "user_id", "123"))

	userID, err := getUserIDFromRequest(req)

	assert.NoError(t, err)
	assert.Equal(t, 123, userID)
}

func TestGetUserIDFromRequestInvalid(t *testing.T) {
	req, _ := http.NewRequest("GET", "/", nil)
	req = req.WithContext(context.WithValue(req.Context(), "user_id", "invalid"))

	_, err := getUserIDFromRequest(req)

	assert.Error(t, err)
	assert.Equal(t, "invalid user ID", err.Error())
}