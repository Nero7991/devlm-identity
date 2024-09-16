package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Nero7991/devlm/devlm-identity/internal/auth"
	"github.com/Nero7991/devlm/devlm-identity/internal/user"
	"github.com/Nero7991/devlm/devlm-identity/internal/ssh"
	"github.com/Nero7991/devlm/devlm-identity/pkg/database"
	"github.com/Nero7991/devlm/devlm-identity/pkg/middleware"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/google/uuid"
)

func loadEnv() error {
	if err := godotenv.Load(); err != nil {
		return err
	}
	return nil
}

func main() {
	logger := log.New(os.Stdout, "devlm-identity: ", log.LstdFlags|log.Lshortfile)

	if err := loadEnv(); err != nil {
		logger.Printf("Warning: Error loading .env file: %v", err)
	}

	requiredEnvVars := []string{"DB_HOST", "DB_PORT", "DB_USER", "DB_PASSWORD", "DB_NAME", "JWT_SECRET_KEY", "JWT_REFRESH_SECRET_KEY"}
	for _, envVar := range requiredEnvVars {
		if os.Getenv(envVar) == "" {
			logger.Fatalf("Required environment variable %s is not set", envVar)
		}
	}

	db, err := database.NewPostgresDB()
	if err != nil {
		logger.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	if err := db.MigrateDatabase(); err != nil {
		logger.Fatalf("Failed to migrate database: %v", err)
	}
	logger.Println("Database migration completed successfully")

	if err := db.CheckDatabaseSchema(); err != nil {
		logger.Fatalf("Database schema check failed: %v", err)
	}
	logger.Println("Database schema check passed")

	sshService := ssh.NewService(db, logger)
	userService := user.NewService(db, logger, sshService)
	authService := auth.NewService(db, logger, userService, sshService)

	router := mux.NewRouter()

	debugMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger.Printf("Debug - Request: %s %s", r.Method, r.URL.Path)
			logger.Printf("Debug - Headers: %v", r.Header)
			rawBody, ok := r.Context().Value("rawBody").([]byte)
			if ok {
				logger.Printf("Debug - Raw request body: %s", string(rawBody))
			} else {
				logger.Printf("Debug - Raw request body not available in context")
			}
			next.ServeHTTP(w, r)
		})
	}

	router.Use(middleware.RecoveryMiddleware)
	router.Use(middleware.JSONResponse)
	router.Use(middleware.BodyParserMiddleware)
	router.Use(debugMiddleware)
	router.Use(middleware.LoggingMiddleware)

	auth.RegisterRoutes(router, authService)

	userRouter := router.PathPrefix("/api/users").Subrouter()
	userRouter.Use(func(next http.Handler) http.Handler {
		return authService.AuthMiddleware(next.ServeHTTP)
	})
	userRouter.Use(func(next http.Handler) http.Handler {
		return authService.AdminMiddleware(next)
	})
	user.RegisterRoutes(userRouter, userService)

	sshRouter := router.PathPrefix("/api/ssh").Subrouter()
	sshRouter.Use(func(next http.Handler) http.Handler {
		return authService.AuthMiddleware(next.ServeHTTP)
	})
	ssh.RegisterRoutes(sshRouter, sshService)

	router.HandleFunc("/api/v1/users/register", authService.Register).Methods("POST")
	router.HandleFunc("/api/v1/users/login", authService.Login).Methods("POST")
	router.HandleFunc("/api/v1/users/forgot-password", authService.ForgotPassword).Methods("POST")
	router.HandleFunc("/api/v1/users/reset-password", authService.ResetPassword).Methods("POST")

	router.HandleFunc("/auth/assign-role", func(w http.ResponseWriter, r *http.Request) {
		authService.AdminMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger.Printf("Debug - Entering AssignRole handler")

			var assignRoleRequest struct {
				UserID uuid.UUID `json:"user_id"`
				Role   string    `json:"role"`
			}

			if err := json.NewDecoder(r.Body).Decode(&assignRoleRequest); err != nil {
				logger.Printf("Error decoding AssignRole request: %v", err)
				http.Error(w, "Invalid request body", http.StatusBadRequest)
				return
			}

			logger.Printf("Debug - AssignRole request: UserID=%s, Role=%s", assignRoleRequest.UserID, assignRoleRequest.Role)

			user, err := authService.GetUserByID(assignRoleRequest.UserID)
			if err != nil {
				logger.Printf("Error retrieving user: %v", err)
				http.Error(w, "User not found", http.StatusNotFound)
				return
			}

			if err := user.UpdateRole(assignRoleRequest.Role); err != nil {
				logger.Printf("Error updating user role: %v", err)
				http.Error(w, "Invalid role", http.StatusBadRequest)
				return
			}

			user.UpdatedAt = time.Now()

			if err := authService.UpdateUser(user); err != nil {
				logger.Printf("Error saving updated user: %v", err)
				http.Error(w, "Failed to assign role", http.StatusInternalServerError)
				return
			}

			logger.Printf("Debug - Role assigned successfully: UserID=%s, Role=%s", assignRoleRequest.UserID, assignRoleRequest.Role)
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{"message": "Role assigned successfully"})

			logger.Printf("Debug - Exiting AssignRole handler")
		})).ServeHTTP(w, r)
	}).Methods("POST")

	router.HandleFunc("/api/users/{id}/role", authService.AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userService.GetUserRole(w, r)
	}))).Methods("GET")

	router.PathPrefix("/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Printf("Debug - Catch-all route hit: %s %s", r.Method, r.URL.Path)
		logger.Printf("Debug - Headers: %+v", r.Header)
		logger.Printf("Debug - Query params: %+v", r.URL.Query())
		http.Error(w, "Not Found", http.StatusNotFound)
	})

	logger.Println("Debug - Registered routes:")
	router.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
		path, _ := route.GetPathTemplate()
		methods, _ := route.GetMethods()
		logger.Printf("Debug - Route: %s %v", path, methods)
		return nil
	})

	srv := &http.Server{
		Addr:         ":8080",
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		logger.Printf("Starting server on %s", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("Failed to start server: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	logger.Println("Server is shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Fatalf("Server forced to shutdown: %v", err)
	}

	logger.Println("Server exited")
}