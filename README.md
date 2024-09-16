# DevLM Identity Service

## Overview

The DevLM Identity Service is a crucial component of the DevLM project, responsible for user authentication, authorization, and management. It provides a secure and scalable solution for handling user identities, roles, and access control across the DevLM ecosystem.

## Key Features

- User registration and authentication
- Role-based access control (RBAC)
- JWT-based token management with refresh tokens
- Password reset and recovery
- SSH key management for remote development
- User profile management
- Rate limiting to prevent abuse

## Setup Instructions

1. Clone the repository:
   ```
   git clone https://github.com/Nero7991/devlm.git
   cd devlm/devlm-identity
   ```

2. Set up environment variables:
   Copy the `.env.example` file to `.env` and fill in the required values:
   ```
   cp .env.example .env
   ```
   Edit the `.env` file with your database credentials, JWT secret keys, and other configuration options.

3. Install dependencies:
   ```
   go mod tidy
   ```

4. Start the service:
   ```
   go run cmd/api/main.go
   ```

The service will start on `http://localhost:8080` by default.

## API Documentation

### Authentication Endpoints

#### Register a new user
- **POST** `/auth/register`
- Request body:
  ```json
  {
    "username": "string",
    "email": "string",
    "password": "string",
    "role": "string" (optional)
  }
  ```
- Response: 201 Created

#### Login
- **POST** `/auth/login`
- Request body:
  ```json
  {
    "email": "string",
    "password": "string"
  }
  ```
- Response: 200 OK
  ```json
  {
    "token": "string",
    "refresh_token": "string"
  }
  ```

#### Forgot Password
- **POST** `/auth/forgot-password`
- Request body:
  ```json
  {
    "email": "string"
  }
  ```
- Response: 200 OK

#### Reset Password
- **POST** `/auth/reset-password`
- Request body:
  ```json
  {
    "email": "string",
    "token": "string",
    "new_password": "string"
  }
  ```
- Response: 200 OK

#### Logout
- **POST** `/auth/logout`
- Headers: `Authorization: Bearer <token>`
- Response: 200 OK

#### Refresh Token
- **POST** `/auth/refresh`
- Request body:
  ```json
  {
    "refresh_token": "string"
  }
  ```
- Response: 200 OK
  ```json
  {
    "token": "string"
  }
  ```

#### Change Password
- **POST** `/auth/change-password`
- Headers: `Authorization: Bearer <token>`
- Request body:
  ```json
  {
    "old_password": "string",
    "new_password": "string"
  }
  ```
- Response: 200 OK

#### Assign Role (Admin only)
- **POST** `/auth/assign-role`
- Headers: `Authorization: Bearer <token>`
- Request body:
  ```json
  {
    "user_id": "uuid",
    "role": "string"
  }
  ```
- Response: 200 OK

### User Management Endpoints

#### Get User Role
- **GET** `/api/users/{id}/role`
- Headers: `Authorization: Bearer <token>`
- Response: 200 OK
  ```json
  {
    "role": "string"
  }
  ```

#### List SSH Keys
- **GET** `/auth/ssh-keys`
- Headers: `Authorization: Bearer <token>`
- Response: 200 OK
  ```json
  [
    {
      "id": "uuid",
      "user_id": "uuid",
      "name": "string",
      "public_key": "string",
      "created_at": "string"
    }
  ]
  ```

#### Add SSH Key
- **POST** `/auth/ssh-keys`
- Headers: `Authorization: Bearer <token>`
- Request body:
  ```json
  {
    "name": "string",
    "public_key": "string"
  }
  ```
- Response: 201 Created

#### Delete SSH Key
- **DELETE** `/auth/ssh-keys/{id}`
- Headers: `Authorization: Bearer <token>`
- Response: 200 OK

#### Get User Profile
- **GET** `/auth/profile`
- Headers: `Authorization: Bearer <token>`
- Response: 200 OK
  ```json
  {
    "id": "uuid",
    "username": "string",
    "email": "string",
    "role": "string",
    "created_at": "string",
    "updated_at": "string"
  }
  ```

## Security Considerations

- All endpoints, except for registration and login, require authentication using JWT tokens.
- Passwords are hashed using bcrypt before storage.
- Rate limiting is implemented to prevent brute-force attacks and abuse.
- HTTPS should be used in production to encrypt all traffic.
- JWT tokens are signed using separate secret keys for access tokens and refresh tokens.
- Password reset tokens are generated securely and have a limited lifetime.

## Configuration

The following environment variables can be set in the `.env` file:

- `DB_HOST`: Database host
- `DB_PORT`: Database port
- `DB_USER`: Database user
- `DB_PASSWORD`: Database password
- `DB_NAME`: Database name
- `JWT_SECRET_KEY`: Secret key for signing JWT access tokens
- `JWT_REFRESH_SECRET_KEY`: Secret key for signing JWT refresh tokens

## Development

To run tests:
```
go test ./...
```

To build the service:
```
go build -o devlm-identity cmd/api/main.go
```

## Logging

The service uses extensive logging for all user operations, including:
- User registration
- Login attempts
- Password reset requests
- Role assignments
- SSH key management

Logs include relevant information such as user IDs, timestamps, and operation results while avoiding sensitive data exposure.

## Error Handling

The service provides meaningful error messages for various scenarios, including:
- Invalid input
- Authentication failures
- Authorization errors
- Rate limiting

Error responses are returned in a consistent JSON format with appropriate HTTP status codes.

## Rate Limiting

Rate limiting is implemented for the following endpoints:
- Registration: 10 requests per hour
- Login: 5 requests per minute
- Password reset: 3 requests per hour

This helps prevent abuse and protects the service from potential attacks.

## Contributing

Please read the CONTRIBUTING.md file for details on our code of conduct and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.