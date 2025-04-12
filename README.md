# PAMP Authentication Service

This is an authentication service for the PAMP platform, providing Google OAuth integration and user management with PostgreSQL database.

## Features

- User registration for teachers
- Google OAuth authentication
- JWT token generation and validation
- API documentation with Swagger UI
- SeaORM for database operations

## Prerequisites

- Rust 1.76 or later
- Docker and Docker Compose
- Google OAuth credentials

## Environment Variables

Create a `.env` file in the project root with the following variables:

```
DATABASE_URL=postgres://postgres:postgres@localhost:5432/pamp_auth
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
GOOGLE_REDIRECT_URI=http://localhost:3000/auth/callback/google
JWT_SECRET=a_secure_random_string
RUST_LOG=info
```

## Running with Docker

1. Make sure Docker and Docker Compose are installed
2. Set up your environment variables in `.env` file
3. Run the service with Docker Compose:

```bash
docker-compose up -d
```

4. Access the service at http://localhost:3000
5. Access API documentation at http://localhost:3000/swagger-ui

## Development Setup

1. Install Rust (https://www.rust-lang.org/tools/install)
2. Install PostgreSQL
3. Create a database for the service
4. Set up your environment variables
5. Run the service:

```bash
cargo run
```

## Database Management

The service uses SeaORM, which automatically creates the database schema on startup if it doesn't exist. No manual migrations are needed.

## API Endpoints

- `GET /` - Health check endpoint
- `GET /auth/google` - Initiate Google OAuth login
- `GET /auth/callback/google` - Google OAuth callback
- `POST /auth/register/teacher` - Register a new teacher

## User Registration Process

1. Register a teacher account with `POST /auth/register/teacher`
2. Login using Google OAuth at `GET /auth/google`
3. Google redirects to the callback URL with an authorization code
4. The service verifies the user exists in the database
5. If the user exists, a JWT token is issued

## Security

- Passwords are hashed using Argon2
- Authentication is handled via JWT tokens
- CSRF protection is implemented for OAuth flow
