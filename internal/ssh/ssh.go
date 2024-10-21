package ssh

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/Nero7991/devlm/devlm-identity/pkg/database"
	"github.com/Nero7991/devlm/devlm-identity/pkg/models"
	"github.com/gorilla/mux"
	"github.com/google/uuid"
)

type Service struct {
	db     database.PostgresDB
	logger *log.Logger
}

func NewService(db database.PostgresDB, logger *log.Logger) *Service {
	return &Service{db: db, logger: logger}
}

func RegisterRoutes(router *mux.Router, service *Service) {
	router.HandleFunc("/api/v1/auth/ssh-keys", service.AddSSHKeyHandler).Methods("POST")
	router.HandleFunc("/api/v1/auth/ssh-keys", service.ListSSHKeysHandler).Methods("GET")
	router.HandleFunc("/api/v1/auth/ssh-keys/{key_id}", service.DeleteSSHKeyHandler).Methods("DELETE")
}

func (s *Service) DeleteSSHKeyHandler(w http.ResponseWriter, r *http.Request) {
	s.logger.Printf("DeleteSSHKeyHandler: Starting")
	userID, ok := r.Context().Value("userID").(uuid.UUID)
	if !ok {
		s.logger.Printf("DeleteSSHKeyHandler: Failed to get userID from context: %v", r.Context().Value("userID"))
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	s.logger.Printf("DeleteSSHKeyHandler: User ID from context: %s", userID)

	vars := mux.Vars(r)
	keyID, err := uuid.Parse(vars["key_id"])
	if err != nil {
		s.logger.Printf("DeleteSSHKeyHandler: Invalid key ID: %s", vars["key_id"])
		http.Error(w, "Invalid key ID", http.StatusBadRequest)
		return
	}

	s.logger.Printf("DeleteSSHKeyHandler: Attempting to delete SSH key for user ID: %s, key ID: %s", userID, keyID)

	err = s.DeleteSSHKey(userID, keyID)
	if err != nil {
		s.logger.Printf("DeleteSSHKeyHandler: Failed to delete SSH key: %v", err)
		if err == database.ErrSSHKeyNotFound {
			http.Error(w, "SSH key not found", http.StatusNotFound)
		} else {
			http.Error(w, "Failed to delete SSH key", http.StatusInternalServerError)
		}
		return
	}

	s.logger.Printf("DeleteSSHKeyHandler: SSH key deleted successfully for user ID=%s, key ID=%s", userID, keyID)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "SSH key deleted successfully"})
}

func (s *Service) ListSSHKeysHandler(w http.ResponseWriter, r *http.Request) {
	s.logger.Printf("ListSSHKeysHandler: Starting")
	userID, ok := r.Context().Value("userID").(uuid.UUID)
	if !ok {
		s.logger.Printf("ListSSHKeysHandler: Failed to get userID from context: %v", r.Context().Value("userID"))
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	s.logger.Printf("ListSSHKeysHandler: User ID from context: %s", userID)

	s.logger.Printf("ListSSHKeysHandler: Attempting to list SSH keys for user ID: %s", userID)

	sshKeys, err := s.ListSSHKeys(userID)
	if err != nil {
		s.logger.Printf("ListSSHKeysHandler: Failed to list SSH keys: %v", err)
		http.Error(w, "Failed to list SSH keys", http.StatusInternalServerError)
		return
	}

	s.logger.Printf("ListSSHKeysHandler: Successfully listed %d SSH keys for user ID: %s", len(sshKeys), userID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sshKeys)
}

func (s *Service) AddSSHKeyHandler(w http.ResponseWriter, r *http.Request) {
	s.logger.Printf("AddSSHKeyHandler: Starting")
	userID, ok := r.Context().Value("userID").(uuid.UUID)
	if !ok {
		s.logger.Printf("AddSSHKeyHandler: Failed to get userID from context: %v", r.Context().Value("userID"))
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	s.logger.Printf("AddSSHKeyHandler: User ID from context: %s", userID)

	var sshKeyRequest struct {
		PublicKey string `json:"public_key"`
		Name      string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&sshKeyRequest); err != nil {
		s.logger.Printf("AddSSHKeyHandler: Failed to decode request body: %v", err)
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	s.logger.Printf("AddSSHKeyHandler: Parsed request - PublicKey: %s, Name: %s", sshKeyRequest.PublicKey, sshKeyRequest.Name)

	if sshKeyRequest.PublicKey == "" {
		s.logger.Printf("AddSSHKeyHandler: Public key is empty")
		http.Error(w, "Public key is required", http.StatusBadRequest)
		return
	}

	if sshKeyRequest.Name == "" {
		s.logger.Printf("AddSSHKeyHandler: Name is empty")
		http.Error(w, "Name is required", http.StatusBadRequest)
		return
	}

	s.logger.Printf("AddSSHKeyHandler: Attempting to add SSH key for user ID: %s", userID)

	if err := s.AddSSHKey(userID, sshKeyRequest.Name, sshKeyRequest.PublicKey); err != nil {
		s.logger.Printf("AddSSHKeyHandler: Failed to add SSH key: %v", err)
		http.Error(w, fmt.Sprintf("Failed to add SSH key: %v", err), http.StatusInternalServerError)
		return
	}

	s.logger.Printf("AddSSHKeyHandler: SSH key added successfully for user ID=%s", userID)

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "SSH key added successfully"})
}

func (s *Service) ListSSHKeys(userID uuid.UUID) ([]models.SSHKey, error) {
	s.logger.Printf("ListSSHKeys: Listing SSH keys for user ID: %s", userID)
	keys, err := s.db.ListSSHKeys(userID)
	if err != nil {
		s.logger.Printf("ListSSHKeys: Failed to list SSH keys from database for user ID %s: %v", userID, err)
		return nil, err
	}
	s.logger.Printf("ListSSHKeys: Listed %d SSH keys from database for user ID %s", len(keys), userID)
	return keys, nil
}

func (s *Service) AddSSHKey(userID uuid.UUID, name, publicKey string) error {
	s.logger.Printf("AddSSHKey: Adding SSH key for user ID: %s, Name: %s", userID, name)
	if err := s.db.AddSSHKey(userID, name, publicKey); err != nil {
		s.logger.Printf("AddSSHKey: Failed to add SSH key to database for user ID %s: %v", userID, err)
		return fmt.Errorf("failed to add SSH key: %v", err)
	}
	s.logger.Printf("AddSSHKey: Successfully added SSH key for user ID: %s", userID)
	return nil
}

func (s *Service) DeleteSSHKey(userID, keyID uuid.UUID) error {
	s.logger.Printf("DeleteSSHKey: Deleting SSH key for user ID: %s, Key ID: %s", userID, keyID)
	err := s.db.DeleteSSHKey(userID, keyID)
	if err != nil {
		if err == database.ErrSSHKeyNotFound {
			s.logger.Printf("DeleteSSHKey: SSH key not found for user ID %s, Key ID %s", userID, keyID)
			return database.ErrSSHKeyNotFound
		}
		s.logger.Printf("DeleteSSHKey: Failed to delete SSH key from database for user ID %s, Key ID %s: %v", userID, keyID, err)
		return err
	}
	s.logger.Printf("DeleteSSHKey: Successfully deleted SSH key for user ID: %s, Key ID: %s", userID, keyID)
	return nil
}