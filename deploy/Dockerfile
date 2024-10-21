ACTION: MULTI: devlm-identity/deploy/Dockerfile, devlm-identity/cmd/api/main.go, devlm-identity/config/config.yaml, devlm-identity/internal/ssh/ssh.go; MODIFY: devlm-identity/deploy/Dockerfile

GOALS: Create a proper Dockerfile for the devlm-identity service to enable containerization and deployment.

REASON: The Dockerfile is currently empty, preventing proper deployment of the devlm-identity service. By creating a suitable Dockerfile, we can containerize the service, ensuring consistent deployment across environments and facilitating testing of the SSH endpoints.

# Use the official Golang image as the base image
FROM golang:1.19-alpine AS builder

# Set the working directory inside the container
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download all dependencies
RUN go mod download

# Copy the source code into the container
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o devlm-identity ./cmd/api

# Use a minimal alpine image for the final stage
FROM alpine:3.14

# Set the working directory
WORKDIR /root/

# Copy the binary from the builder stage
COPY --from=builder /app/devlm-identity .

# Copy the config file
COPY --from=builder /app/config/config.yaml ./config/

# Expose the port the app runs on
EXPOSE 8080

# Run the binary
CMD ["./devlm-identity"]