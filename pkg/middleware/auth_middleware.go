package middleware

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/Nero7991/devlm/devlm-identity/internal/auth"
	"github.com/Nero7991/devlm/devlm-identity/pkg/database"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/time/rate"
)

// AuthMiddleware is a middleware that checks for a valid JWT token in the Authorization header
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Entering AuthMiddleware for request: %s %s", r.Method, r.URL.Path)
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			log.Println("Missing Authorization header")
			ErrorResponse(w, "Missing Authorization header", http.StatusUnauthorized)
			return
		}

		log.Printf("Authorization header: %s", authHeader)

		token := authHeader
		if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
			token = authHeader[7:]
			log.Printf("Extracted token: %s", token)
		}

		claims, err := auth.ValidateToken(token)
		if err != nil {
			log.Printf("Token validation failed: %v", err)
			ErrorResponse(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		log.Printf("Token validated successfully. Claims: %+v", claims)

		// Check token expiration
		exp, ok := (*claims)["exp"].(float64)
		if !ok {
			log.Printf("Failed to extract expiration time from claims: %+v", *claims)
			ErrorResponse(w, "Invalid token claims", http.StatusUnauthorized)
			return
		}
		if time.Now().Unix() > int64(exp) {
			log.Printf("Token has expired. Current time: %v, Expiration time: %v", time.Now().Unix(), int64(exp))
			ErrorResponse(w, "Token has expired", http.StatusUnauthorized)
			return
		}

		// Add the user ID and role from the token claims to the request context
		userID, ok := (*claims)["user_id"].(string)
		if !ok {
			log.Printf("Failed to extract user_id from claims: %+v", *claims)
			ErrorResponse(w, "Invalid token claims", http.StatusUnauthorized)
			return
		}

		role, ok := (*claims)["role"].(string)
		if !ok {
			log.Printf("Failed to extract role from claims: %+v", *claims)
			ErrorResponse(w, "Invalid token claims", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "userID", userID)
		ctx = context.WithValue(ctx, "userRole", role)
		ctx = context.WithValue(ctx, "claims", claims)

		log.Printf("Added userID (%v), userRole (%s), and claims to context", userID, role)

		// Log all context values for debugging
		contextValues := map[string]interface{}{
			"userID":   userID,
			"userRole": role,
			"claims":   *claims,
		}
		log.Printf("Context values: %+v", contextValues)

		next.ServeHTTP(w, r.WithContext(ctx))
		log.Printf("Exiting AuthMiddleware for request: %s %s", r.Method, r.URL.Path)
	})
}

// AdminMiddleware is a middleware that checks if the user has the admin role
func AdminMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Entering AdminMiddleware for request: %s %s", r.Method, r.URL.Path)
		
		// Log all context values
		log.Printf("Context values in AdminMiddleware: %+v", r.Context())

		claims, ok := r.Context().Value("claims").(*jwt.MapClaims)
		if !ok {
			log.Printf("Failed to get claims from context. Context values: %+v", r.Context())
			ErrorResponse(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		log.Printf("Claims retrieved from context: %+v", *claims)

		role, ok := (*claims)["role"].(string)
		if !ok {
			log.Printf("Failed to extract role from claims: %+v", *claims)
			ErrorResponse(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		log.Printf("Checking user role. Required: admin, Actual: %s", role)

		if role != "admin" {
			log.Printf("Insufficient permissions. Required: admin, Actual: %s", role)
			ErrorResponse(w, "Insufficient permissions", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
		log.Printf("Exiting AdminMiddleware for request: %s %s", r.Method, r.URL.Path)
	})
}

// RequireRole is a middleware that checks if the user has the required role
func RequireRole(role string, db database.PostgresDB, logger *log.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userRole, ok := r.Context().Value("userRole").(string)
			if !ok {
				logger.Printf("User role not found in context")
				ErrorResponse(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			logger.Printf("Checking user role. Required: %s, Actual: %s", role, userRole)

			if userRole != role {
				logger.Printf("Insufficient permissions. Required: %s, Actual: %s", role, userRole)
				ErrorResponse(w, "Insufficient permissions", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// JSONResponse wraps an HTTP handler and ensures the response is in JSON format
func JSONResponse(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		next.ServeHTTP(w, r)
	})
}

// ErrorResponse sends a JSON error response
func ErrorResponse(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// LoggingMiddleware logs information about each request
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		log.Printf("Started %s %s", r.Method, r.URL.Path)

		// Log request headers
		log.Printf("Request Headers: %+v", r.Header)

		// Read and log the request body
		var bodyBytes []byte
		if r.Body != nil {
			bodyBytes, _ = ioutil.ReadAll(r.Body)
			log.Printf("Request Body: %s", string(bodyBytes))
			// Restore the body to the request
			r.Body = ioutil.NopCloser(strings.NewReader(string(bodyBytes)))
		}

		// Create a response wrapper to capture the response
		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(rw, r)

		duration := time.Since(start)
		log.Printf("Completed %s %s in %v with status %d", r.Method, r.URL.Path, duration, rw.statusCode)

		// Log response headers
		log.Printf("Response Headers: %+v", rw.Header())

		// Log response body if it's JSON
		if strings.Contains(rw.Header().Get("Content-Type"), "application/json") {
			log.Printf("Response Body: %s", rw.body.String())
		}
	})
}

// RecoveryMiddleware recovers from panics and logs the error
func RecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("panic: %v\n%s", err, debug.Stack())
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// RateLimitMiddleware implements rate limiting for the specified handler
func RateLimitMiddleware(limiter *rate.Limiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow() {
			ErrorResponse(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// responseWriter is a custom ResponseWriter that captures the status code and response body
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	body       strings.Builder
}

func (rw *responseWriter) WriteHeader(statusCode int) {
	rw.statusCode = statusCode
	rw.ResponseWriter.WriteHeader(statusCode)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	rw.body.Write(b)
	return rw.ResponseWriter.Write(b)
}

// BodyParserMiddleware reads the request body and stores it in the context
func BodyParserMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("BodyParserMiddleware: Entering for request: %s %s", r.Method, r.URL.Path)
		if r.Body == nil {
			log.Printf("BodyParserMiddleware: Request body is nil")
			next.ServeHTTP(w, r)
			return
		}

		// Only parse body for POST, PUT, and PATCH requests
		if r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" {
			bodyBytes, err := ioutil.ReadAll(r.Body)
			if err != nil {
				log.Printf("BodyParserMiddleware: Error reading request body: %v", err)
				http.Error(w, "Error reading request body", http.StatusBadRequest)
				return
			}
			log.Printf("BodyParserMiddleware: Raw request body: %s", string(bodyBytes))

			// Restore the body to the request
			r.Body = ioutil.NopCloser(strings.NewReader(string(bodyBytes)))

			// Store the body in the context
			ctx := context.WithValue(r.Context(), "rawBody", bodyBytes)

			// Parse JSON if Content-Type is application/json
			if r.Header.Get("Content-Type") == "application/json" {
				var jsonBody map[string]interface{}
				if err := json.Unmarshal(bodyBytes, &jsonBody); err != nil {
					log.Printf("BodyParserMiddleware: Error parsing JSON body: %v", err)
					http.Error(w, "Invalid JSON in request body", http.StatusBadRequest)
					return
				}
				ctx = context.WithValue(ctx, "jsonBody", jsonBody)
				log.Printf("BodyParserMiddleware: Parsed JSON body: %+v", jsonBody)
			}

			r = r.WithContext(ctx)
		}

		log.Printf("BodyParserMiddleware: Context values after processing: %+v", r.Context())
		next.ServeHTTP(w, r)
		log.Printf("BodyParserMiddleware: Exiting for request: %s %s", r.Method, r.URL.Path)
	})
}