package main

import (
	"context"
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

	// Public routes
	router.HandleFunc("/api/v1/users/register", auth.RateLimitMiddleware(authService.RegisterLimiter, authService.Register)).Methods("POST")
	router.HandleFunc("/api/v1/users/login", auth.RateLimitMiddleware(authService.LoginLimiter, authService.Login)).Methods("POST")
	router.HandleFunc("/api/v1/users/forgot-password", auth.RateLimitMiddleware(authService.ResetPasswordLimiter, authService.ForgotPassword)).Methods("POST")
	router.HandleFunc("/api/v1/users/reset-password", authService.ResetPassword).Methods("POST")
	router.HandleFunc("/api/v1/users/refresh-token", authService.RefreshToken).Methods("POST")

	// Protected routes
	router.Handle("/api/v1/users/profile", authService.AuthMiddleware(http.HandlerFunc(authService.GetUserProfile))).Methods("GET")
	router.Handle("/api/v1/users/change-password", authService.AuthMiddleware(http.HandlerFunc(authService.ChangePassword))).Methods("POST")

	// Admin routes
	router.Handle("/api/v1/users", authService.AdminMiddleware(http.HandlerFunc(userService.ListUsers))).Methods("GET")
	router.Handle("/api/v1/users/{id}", authService.AdminMiddleware(http.HandlerFunc(userService.GetUser))).Methods("GET")
	router.Handle("/api/v1/users/{id}", authService.AdminMiddleware(http.HandlerFunc(userService.UpdateUser))).Methods("PUT")
	router.Handle("/api/v1/users/{id}", authService.AdminMiddleware(http.HandlerFunc(userService.DeleteUser))).Methods("DELETE")
	router.Handle("/api/v1/users/{id}/update-role", authService.AdminMiddleware(http.HandlerFunc(userService.UpdateUserRole))).Methods("PATCH")
	router.Handle("/api/v1/users/{id}/role", authService.AdminMiddleware(http.HandlerFunc(userService.GetUserRole))).Methods("GET")
	router.Handle("/api/v1/auth/assign-role", authService.AdminMiddleware(http.HandlerFunc(authService.AssignRole))).Methods("POST")

	// SSH key routes
	router.Handle("/api/v1/auth/ssh-keys", authService.AuthMiddleware(http.HandlerFunc(authService.ListSSHKeys))).Methods("GET")
	router.Handle("/api/v1/auth/ssh-keys", authService.AuthMiddleware(http.HandlerFunc(authService.AddSSHKey))).Methods("POST")
	router.Handle("/api/v1/auth/ssh-keys/{id}", authService.AuthMiddleware(http.HandlerFunc(authService.DeleteSSHKey))).Methods("DELETE")

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