package database

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/Nero7991/devlm/devlm-identity/pkg/models"
	"github.com/google/uuid"
	"github.com/lib/pq"
	_ "github.com/lib/pq"
)

var db *sql.DB

var ErrDuplicateKey = errors.New("duplicate key value violates unique constraint")
var ErrInvalidToken = errors.New("invalid or expired token")
var ErrNoRows = sql.ErrNoRows
var ErrUserNotFound = errors.New("user not found")
var ErrSSHKeyNotFound = errors.New("SSH key not found or doesn't belong to the user")

type Result interface {
	LastInsertId() (int64, error)
	RowsAffected() (int64, error)
}

type Row interface {
	Scan(dest ...interface{}) error
}

type Rows interface {
	Next() bool
	Scan(dest ...interface{}) error
	Close() error
}

type PostgresDB interface {
	Close() error
	CreateUserTable() error
	CreateSSHKeysTable() error
	CreateResetTokensTable() error
	ListUsers(limit, offset int) ([]*models.User, error)
	UpdateUser(user *models.User) error
	DeleteUser(id uuid.UUID) error
	GetUserByID(id uuid.UUID) (*models.User, error)
	GetUserByUsername(username string) (*models.User, error)
	CreateUser(user *models.User) error
	GetUserByEmail(email string) (*models.User, error)
	UpdatePassword(userID uuid.UUID, newPasswordHash string) error
	AddSSHKey(userID uuid.UUID, name, publicKey string) error
	ListSSHKeys(userID uuid.UUID) ([]models.SSHKey, error)
	DeleteSSHKey(userID uuid.UUID, keyID uuid.UUID) error
	StoreResetToken(userID uuid.UUID, token string, expiresAt time.Time) error
	ValidateResetToken(token string) (uuid.UUID, error)
	InvalidateResetToken(token string) error
	UpdateUserPassword(userID uuid.UUID, newPasswordHash string) error
	Exec(query string, args ...interface{}) (Result, error)
	QueryRow(query string, args ...interface{}) Row
	Query(query string, args ...interface{}) (Rows, error)
	GetUserByResetToken(token string) (*models.User, error)
	CheckDatabaseSchema() error
	MigrateDatabase() error
}

type postgresDB struct {
	db     *sql.DB
	logger *log.Logger
}

func NewPostgresDB() (PostgresDB, error) {
	host := os.Getenv("DB_HOST")
	port := os.Getenv("DB_PORT")
	user := os.Getenv("DB_USER")
	password := os.Getenv("DB_PASSWORD")
	dbname := os.Getenv("DB_NAME")

	logger := log.New(os.Stdout, "PostgresDB: ", log.LstdFlags|log.Lshortfile)

	return InitDB(host, port, user, password, dbname, logger)
}

func InitDB(host, port, user, password, dbname string, logger *log.Logger) (PostgresDB, error) {
	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)

	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %v", err)
	}

	err = db.Ping()
	if err != nil {
		return nil, fmt.Errorf("failed to ping database: %v", err)
	}

	logger.Println("Successfully connected to the database")
	return &postgresDB{db: db, logger: logger}, nil
}

func (pdb *postgresDB) Close() error {
	if pdb.db != nil {
		return pdb.db.Close()
	}
	return nil
}

func (pdb *postgresDB) CreateUserTable() error {
	query := `
	CREATE TABLE IF NOT EXISTS users (
		id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
		username VARCHAR(50) UNIQUE NOT NULL,
		email VARCHAR(100) UNIQUE NOT NULL,
		password_hash VARCHAR(255) NOT NULL,
		role VARCHAR(20) NOT NULL DEFAULT 'user',
		created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
		deleted_at TIMESTAMP WITH TIME ZONE,
		creator_id UUID
	)`

	_, err := pdb.db.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to create users table: %v", err)
	}

	pdb.logger.Println("Users table created successfully")
	return nil
}

func (pdb *postgresDB) CreateSSHKeysTable() error {
	query := `
	CREATE TABLE IF NOT EXISTS ssh_keys (
		id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
		user_id UUID NOT NULL,
		name VARCHAR(255) NOT NULL,
		public_key TEXT NOT NULL,
		created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	)`

	_, err := pdb.db.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to create ssh_keys table: %v", err)
	}

	pdb.logger.Println("SSH keys table created successfully")
	return nil
}

func (pdb *postgresDB) CreateResetTokensTable() error {
	query := `
	CREATE TABLE IF NOT EXISTS reset_tokens (
		id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
		user_id UUID NOT NULL,
		token VARCHAR(255) UNIQUE NOT NULL,
		expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
		created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	)`

	_, err := pdb.db.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to create reset_tokens table: %v", err)
	}

	pdb.logger.Println("Reset tokens table created successfully")
	return nil
}

func (pdb *postgresDB) ListUsers(limit, offset int) ([]*models.User, error) {
	query := `SELECT id, username, email, role, created_at, updated_at, deleted_at, creator_id FROM users WHERE deleted_at IS NULL ORDER BY created_at LIMIT $1 OFFSET $2`
	rows, err := pdb.db.Query(query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %v", err)
	}
	defer rows.Close()

	var users []*models.User
	for rows.Next() {
		user := &models.User{}
		err := rows.Scan(&user.ID, &user.Username, &user.Email, &user.Role, &user.CreatedAt, &user.UpdatedAt, &user.DeletedAt, &user.CreatorID)
		if err != nil {
			return nil, fmt.Errorf("failed to scan user: %v", err)
		}
		users = append(users, user)
	}

	pdb.logger.Printf("Listed %d users", len(users))
	return users, nil
}

func (pdb *postgresDB) UpdateUser(user *models.User) error {
	query := `UPDATE users SET username = $1, email = $2, role = $3, updated_at = $4, deleted_at = $5, creator_id = $6 WHERE id = $7`
	_, err := pdb.db.Exec(query, user.Username, user.Email, user.Role, time.Now(), user.DeletedAt, user.CreatorID, user.ID)
	if err != nil {
		return fmt.Errorf("failed to update user: %v", err)
	}
	pdb.logger.Printf("Updated user: ID=%s, Username=%s, Role=%s", user.ID, user.Username, user.Role)
	return nil
}

func (pdb *postgresDB) DeleteUser(id uuid.UUID) error {
	query := `UPDATE users SET deleted_at = $1 WHERE id = $2 AND deleted_at IS NULL`
	result, err := pdb.db.Exec(query, time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to delete user: %v", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return ErrUserNotFound
	}
	pdb.logger.Printf("Soft deleted user: ID=%s", id)
	return nil
}

func (pdb *postgresDB) GetUserByID(id uuid.UUID) (*models.User, error) {
	query := `SELECT id, username, email, password_hash, role, created_at, updated_at, deleted_at, creator_id FROM users WHERE id = $1 AND deleted_at IS NULL`
	user := &models.User{}
	err := pdb.db.QueryRow(query, id).Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.Role, &user.CreatedAt, &user.UpdatedAt, &user.DeletedAt, &user.CreatorID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user by ID: %v", err)
	}
	pdb.logger.Printf("Retrieved user by ID: ID=%s, Username=%s", user.ID, user.Username)
	return user, nil
}

func (pdb *postgresDB) GetUserByUsername(username string) (*models.User, error) {
	query := `SELECT id, username, email, password_hash, role, created_at, updated_at, deleted_at, creator_id FROM users WHERE username = $1 AND deleted_at IS NULL`
	user := &models.User{}
	err := pdb.db.QueryRow(query, username).Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.Role, &user.CreatedAt, &user.UpdatedAt, &user.DeletedAt, &user.CreatorID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user by username: %v", err)
	}
	pdb.logger.Printf("Retrieved user by username: ID=%s, Username=%s", user.ID, user.Username)
	return user, nil
}

func (pdb *postgresDB) CreateUser(user *models.User) error {
	pdb.logger.Printf("Attempting to create user: %+v", user)

	query := `INSERT INTO users (id, username, email, password_hash, role, created_at, updated_at, creator_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	_, err := pdb.db.Exec(query, user.ID, user.Username, user.Email, user.PasswordHash, user.Role, user.CreatedAt, user.UpdatedAt, user.CreatorID)
	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok {
			switch pqErr.Code {
			case "23505": // unique_violation
				pdb.logger.Printf("Duplicate key error for user %s (email: %s): %v", user.Username, user.Email, pqErr.Detail)
				return ErrDuplicateKey
			case "23503": // foreign_key_violation
				pdb.logger.Printf("Foreign key violation for user %s (email: %s): %v", user.Username, user.Email, pqErr.Detail)
			default:
				pdb.logger.Printf("Unexpected database error for user %s (email: %s): %v (Code: %s)", user.Username, user.Email, pqErr.Message, pqErr.Code)
			}
		} else {
			pdb.logger.Printf("Non-PostgreSQL error creating user %s (email: %s): %v", user.Username, user.Email, err)
		}
		return fmt.Errorf("failed to create user: %v", err)
	}
	pdb.logger.Printf("User created successfully: %s (email: %s, id: %s)", user.Username, user.Email, user.ID)
	return nil
}

func (pdb *postgresDB) GetUserByEmail(email string) (*models.User, error) {
	query := `SELECT id, username, email, password_hash, role, created_at, updated_at, deleted_at, creator_id FROM users WHERE email = $1 AND deleted_at IS NULL`
	user := &models.User{}
	err := pdb.db.QueryRow(query, email).Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.Role, &user.CreatedAt, &user.UpdatedAt, &user.DeletedAt, &user.CreatorID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user by email: %v", err)
	}
	pdb.logger.Printf("Retrieved user by email: ID=%s, Username=%s", user.ID, user.Username)
	return user, nil
}

func (pdb *postgresDB) UpdatePassword(userID uuid.UUID, newPasswordHash string) error {
	query := `UPDATE users SET password_hash = $1, updated_at = $2 WHERE id = $3`
	_, err := pdb.db.Exec(query, newPasswordHash, time.Now(), userID)
	if err != nil {
		return fmt.Errorf("failed to update password: %v", err)
	}
	pdb.logger.Printf("Updated password for user: ID=%s", userID)
	return nil
}

func (pdb *postgresDB) AddSSHKey(userID uuid.UUID, name, publicKey string) error {
	query := `INSERT INTO ssh_keys (id, user_id, name, public_key, created_at) VALUES ($1, $2, $3, $4, $5)`
	_, err := pdb.db.Exec(query, uuid.New(), userID, name, publicKey, time.Now())
	if err != nil {
		return fmt.Errorf("failed to add SSH key: %v", err)
	}
	pdb.logger.Printf("Added SSH key for user: ID=%s, Name=%s", userID, name)
	return nil
}

func (pdb *postgresDB) ListSSHKeys(userID uuid.UUID) ([]models.SSHKey, error) {
	pdb.logger.Printf("ListSSHKeys: Listing SSH keys for user ID: %s", userID)
	query := `SELECT id, user_id, name, public_key, created_at FROM ssh_keys WHERE user_id = $1`
	rows, err := pdb.db.Query(query, userID)
	if err != nil {
		pdb.logger.Printf("ListSSHKeys: Failed to query SSH keys: %v", err)
		return nil, fmt.Errorf("failed to list SSH keys: %v", err)
	}
	defer rows.Close()

	var keys []models.SSHKey
	for rows.Next() {
		var key models.SSHKey
		if err := rows.Scan(&key.ID, &key.UserID, &key.Name, &key.PublicKey, &key.CreatedAt); err != nil {
			pdb.logger.Printf("ListSSHKeys: Failed to scan SSH key: %v", err)
			return nil, fmt.Errorf("failed to scan SSH key: %v", err)
		}
		keys = append(keys, key)
	}

	pdb.logger.Printf("ListSSHKeys: Listed %d SSH keys for user ID %s", len(keys), userID)
	return keys, nil
}

func (pdb *postgresDB) DeleteSSHKey(userID uuid.UUID, keyID uuid.UUID) error {
	pdb.logger.Printf("DeleteSSHKey: Attempting to delete SSH key for user ID: %s, key ID: %s", userID, keyID)

	query := `DELETE FROM ssh_keys WHERE id = $1 AND user_id = $2`
	result, err := pdb.db.Exec(query, keyID, userID)
	if err != nil {
		pdb.logger.Printf("DeleteSSHKey: Database error: %v", err)
		return fmt.Errorf("failed to delete SSH key: %v", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		pdb.logger.Printf("DeleteSSHKey: Error getting rows affected: %v", err)
		return fmt.Errorf("failed to get rows affected: %v", err)
	}

	pdb.logger.Printf("DeleteSSHKey: Rows affected: %d", rowsAffected)

	if rowsAffected == 0 {
		pdb.logger.Printf("DeleteSSHKey: No SSH key found for user ID %s, key ID %s", userID, keyID)
		return ErrSSHKeyNotFound
	}

	pdb.logger.Printf("DeleteSSHKey: Successfully deleted SSH key for user ID: %s, key ID: %s", userID, keyID)
	return nil
}

func (pdb *postgresDB) StoreResetToken(userID uuid.UUID, token string, expiresAt time.Time) error {
	query := `INSERT INTO reset_tokens (id, user_id, token, expires_at, created_at) VALUES ($1, $2, $3, $4, $5)`
	_, err := pdb.db.Exec(query, uuid.New(), userID, token, expiresAt, time.Now())
	if err != nil {
		return fmt.Errorf("failed to store reset token: %v", err)
	}
	pdb.logger.Printf("Stored reset token for user: ID=%s", userID)
	return nil
}

func (pdb *postgresDB) ValidateResetToken(token string) (uuid.UUID, error) {
	query := `SELECT user_id FROM reset_tokens WHERE token = $1 AND expires_at > CURRENT_TIMESTAMP`
	var userID uuid.UUID
	err := pdb.db.QueryRow(query, token).Scan(&userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return uuid.Nil, ErrInvalidToken
		}
		return uuid.Nil, fmt.Errorf("failed to validate reset token: %v", err)
	}
	pdb.logger.Printf("Validated reset token for user: ID=%s", userID)
	return userID, nil
}

func (pdb *postgresDB) InvalidateResetToken(token string) error {
	query := `DELETE FROM reset_tokens WHERE token = $1`
	_, err := pdb.db.Exec(query, token)
	if err != nil {
		return fmt.Errorf("failed to invalidate reset token: %v", err)
	}
	pdb.logger.Printf("Invalidated reset token")
	return nil
}

func (pdb *postgresDB) UpdateUserPassword(userID uuid.UUID, newPasswordHash string) error {
	tx, err := pdb.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %v", err)
	}

	updateQuery := `UPDATE users SET password_hash = $1, updated_at = $2 WHERE id = $3`
	_, err = tx.Exec(updateQuery, newPasswordHash, time.Now(), userID)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to update password: %v", err)
	}

	deleteQuery := `DELETE FROM reset_tokens WHERE user_id = $1`
	_, err = tx.Exec(deleteQuery, userID)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to delete reset tokens: %v", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %v", err)
	}

	pdb.logger.Printf("Updated password and invalidated reset tokens for user: ID=%s", userID)
	return nil
}

func (pdb *postgresDB) Exec(query string, args ...interface{}) (Result, error) {
	return pdb.db.Exec(query, args...)
}

func (pdb *postgresDB) QueryRow(query string, args ...interface{}) Row {
	return pdb.db.QueryRow(query, args...)
}

func (pdb *postgresDB) Query(query string, args ...interface{}) (Rows, error) {
	return pdb.db.Query(query, args...)
}

func (pdb *postgresDB) GetUserByResetToken(token string) (*models.User, error) {
	query := `
		SELECT u.id, u.username, u.email, u.password_hash, u.role, u.created_at, u.updated_at, u.deleted_at, u.creator_id
		FROM users u 
		JOIN reset_tokens rt ON u.id = rt.user_id 
		WHERE rt.token = $1 AND rt.expires_at > CURRENT_TIMESTAMP
	`
	user := &models.User{}
	err := pdb.db.QueryRow(query, token).Scan(
		&user.ID, &user.Username, &user.Email, &user.PasswordHash,
		&user.Role, &user.CreatedAt, &user.UpdatedAt, &user.DeletedAt, &user.CreatorID,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user by reset token: %v", err)
	}
	pdb.logger.Printf("Retrieved user by reset token: ID=%s, Username=%s", user.ID, user.Username)
	return user, nil
}

func (pdb *postgresDB) CheckDatabaseSchema() error {
	usersQuery := `
	SELECT column_name, data_type 
	FROM information_schema.columns 
	WHERE table_name = 'users'
	`
	rows, err := pdb.db.Query(usersQuery)
	if err != nil {
		return fmt.Errorf("failed to query users table schema: %v", err)
	}
	defer rows.Close()

	expectedColumns := map[string]string{
		"id":            "uuid",
		"username":      "character varying",
		"email":         "character varying",
		"password_hash": "character varying",
		"role":          "character varying",
		"created_at":    "timestamp with time zone",
		"updated_at":    "timestamp with time zone",
		"deleted_at":    "timestamp with time zone",
		"creator_id":    "uuid",
	}

	for rows.Next() {
		var columnName, dataType string
		if err := rows.Scan(&columnName, &dataType); err != nil {
			return fmt.Errorf("failed to scan column info: %v", err)
		}
		expectedType, exists := expectedColumns[columnName]
		if !exists {
			return fmt.Errorf("unexpected column in users table: %s", columnName)
		}
		if dataType != expectedType {
			return fmt.Errorf("column %s has unexpected data type: got %s, want %s", columnName, dataType, expectedType)
		}
		delete(expectedColumns, columnName)
	}

	if len(expectedColumns) > 0 {
		return fmt.Errorf("missing columns in users table: %v", expectedColumns)
	}

	pdb.logger.Println("Database schema check passed successfully")
	return nil
}

func (pdb *postgresDB) MigrateDatabase() error {
	pdb.logger.Println("Starting database migration")

	// Create uuid-ossp extension if it doesn't exist
	_, err := pdb.db.Exec("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\"")
	if err != nil {
		return fmt.Errorf("failed to create uuid-ossp extension: %v", err)
	}
	pdb.logger.Println("uuid-ossp extension created or already exists")

	// Start a transaction
	tx, err := pdb.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %v", err)
	}
	defer tx.Rollback()

	// Create users table if it doesn't exist
	_, err = tx.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			username VARCHAR(50) UNIQUE NOT NULL,
			email VARCHAR(100) UNIQUE NOT NULL,
			password_hash VARCHAR(255) NOT NULL,
			role VARCHAR(20) NOT NULL DEFAULT 'user',
			created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
			deleted_at TIMESTAMP WITH TIME ZONE,
			creator_id UUID
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create users table: %v", err)
	}
	pdb.logger.Println("Users table created or already exists")

	// Create ssh_keys table if it doesn't exist
	_, err = tx.Exec(`
		CREATE TABLE IF NOT EXISTS ssh_keys (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			user_id UUID NOT NULL,
			name VARCHAR(255) NOT NULL,
			public_key TEXT NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create ssh_keys table: %v", err)
	}
	pdb.logger.Println("SSH keys table created or already exists")

	// Create reset_tokens table if it doesn't exist
	_, err = tx.Exec(`
		CREATE TABLE IF NOT EXISTS reset_tokens (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			user_id UUID NOT NULL,
			token VARCHAR(255) UNIQUE NOT NULL,
			expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create reset_tokens table: %v", err)
	}
	pdb.logger.Println("Reset tokens table created or already exists")

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %v", err)
	}

	pdb.logger.Println("Database migration completed successfully")
	return nil
}