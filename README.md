# DVWAPI

Damn Vulnerable Web API - An intentionally insecure REST API for security testing and training.

> [!WARNING]
> Running this on the open internet will leave the host vulnerable. It is recommended to use the supplied container in a 
> restricted access environment instead. If you choose to host this on the public internet you do so at your own risk!!

## Overview

DVWAPI is a deliberately vulnerable web application designed for learning and practicing web API security testing. It contains common vulnerabilities found in web APIs including exposed sensitive endpoints, lack of authentication, and information disclosure.

## Quick Start

### Using Docker Hub (Recommended)

Pull and run the latest image from Docker Hub:

```bash
docker pull trapdoorsec/dvwapi:latest
docker run -d -p 7341:7341 --name dvwapi trapdoorsec/dvwapi:latest
```

The API will be available at `http://localhost:7341`

### Using Docker Compose

```bash
docker-compose up -d
```

### Using Makefile

```bash
# Build locally
make build

# Run container
make run

# View logs
make logs

# Stop container
make stop
```

## Building

### Native Build

```bash
cargo build --release
```

The compiled binary will be available at `target/release/dvwapi`.

### Docker Build

Build locally:

```bash
docker build -t dvwapi:latest .
```

Or use the Makefile:

```bash
make build
```

## Usage

### Docker Hub

Pull the latest image:

```bash
docker pull trapdoorsec/dvwapi:latest
```

Run the container:

```bash
docker run -d -p 7341:7341 --name dvwapi trapdoorsec/dvwapi:latest
```

Run with custom options:

```bash
docker run -d -p 8080:8080 --name dvwapi trapdoorsec/dvwapi:latest --port 8080 --log-level debug
```

Stop the container:

```bash
docker stop dvwapi
docker rm dvwapi
```

### Docker Compose

Start the service:

```bash
docker-compose up -d
```

View logs:

```bash
docker-compose logs -f
```

Stop the service:

```bash
docker-compose down
```

### Native

Run with default settings (0.0.0.0:7341):

```bash
./dvwapi
```

### Command Line Options

- `-i, --ip <IP>` - IP address to bind to (default: 0.0.0.0)
- `-p, --port <PORT>` - Port number to listen on (default: 7341)
- `-c, --colored <true|false>` - Enable colored console logging (default: true)
- `-l, --log-level <LEVEL>` - Set log level: trace, debug, info, warn, error (default: info)

### Examples (Native)

```bash
# Bind to localhost on port 8080
./dvwapi --ip 127.0.0.1 --port 8080

# Enable debug logging
./dvwapi --log-level debug

# Disable colored output
./dvwapi --colored false
```

## API Endpoints

The API supports three versions with different response formats and features.

### Root Endpoint

- `GET /` - API status (returns v1 format)

### API Version 1 (Simple)

**Public Endpoints:**
- `GET /api/v1/` - API version info
- `GET /api/v1/users` - List all users
- `GET /api/v1/users/{id}` - Get user by ID
- `POST /api/v1/users` - Create new user

**Vulnerable Endpoints:**
- `GET /api/v1/debug/config` - Exposes secrets
- `GET /api/v1/admin` - Admin panel
- `GET /api/v1/.env` - Environment file
- `GET /api/v1/env` - Dumps environment variables (AWS keys, DB credentials, etc.)

### API Version 2 (Wrapped Responses)

Returns data wrapped in `data` and `meta` objects with timestamps.

**Public Endpoints:**
- `GET /api/v2/` - API version info
- `GET /api/v2/users` - List users with metadata
- `GET /api/v2/users/{id}` - Get user with metadata
- `POST /api/v2/users` - Create user with metadata

**Vulnerable Endpoints:**
- `GET /api/v2/debug/config` - Configuration with additional secrets
- `GET /api/v2/admin` - Admin panel
- `GET /api/v2/.env` - Environment file
- `GET /api/v2/env` - Dumps environment variables with metadata

### API Version 3 (Full Response Envelope)

Returns structured responses with status, data, and metadata including request IDs.

**Public Endpoints:**
- `GET /api/v3/` - API version info with endpoint list
- `GET /api/v3/health` - Health check endpoint (also: `/healthz`, `/healthcheck`, `/ready`, `/readyz`, `/live`, `/livez`, `/status`)
- `GET /api/v3/ping` - Ping endpoint
- `GET /api/v3/users` - List users with pagination info
- `GET /api/v3/users/{id}` - Get user with permissions
- `POST /api/v3/users` - Create user with full metadata

**Vulnerable Endpoints:**
- `GET /api/v3/debug/config` - Exposes production secrets including JWT
- `GET /api/v3/admin` - Admin panel
- `GET /api/v3/.env` - Environment file
- `GET /api/v3/env` - Full environment variable dump with severity warnings

### Command Injection Vulnerability

The API has intentionally vulnerable endpoints that allow command injection through path parameters:

- `GET /api/{version}/version-info` - Version validation with command injection
- `GET /api/{version}/check` - API version check with command injection

### Swagger UI RCE Vulnerability

The API exposes Swagger/OpenAPI documentation endpoints with RCE vulnerabilities through unsafe spec generation:

- `GET /swagger` - Swagger UI documentation viewer
- `GET /redoc` - ReDoc documentation viewer
- `GET /swagger.json` - Swagger JSON spec
- `GET /api-docs` - API documentation
- `GET /swagger/generate?title={value}` - Generate custom spec (vulnerable to command injection)
- `GET /swagger/upload/{spec}` - Upload custom spec (vulnerable to command injection)

**Exploitation Examples:**

```bash
# Execute whoami command via query parameter
curl http://localhost:7341/swagger/generate?title=\$\(whoami\)

# Execute id command
curl http://localhost:7341/swagger/generate?title=API\;id\;

# Execute commands via upload endpoint
curl http://localhost:7341/swagger/upload/test\;whoami\;

# Chain multiple commands
curl "http://localhost:7341/swagger/generate?title=API\;ls%20-la\;pwd"
```

The vulnerability exists because the endpoints use shell commands to "validate" user input during spec generation.

### GraphQL API

The API includes GraphQL endpoints with intentional vulnerabilities:

- `GET /graphql` - GraphQL Playground (interactive query interface)
- `POST /graphql` - GraphQL API endpoint
- `GET /graphql/playground` - Alternative playground URL

**Available Queries:**

```graphql
# Get all users
query {
  users {
    id
    name
  }
}

# Get user by ID
query {
  user(id: 1) {
    id
    name
  }
}

# VULNERABLE: Exposed secrets
query {
  secrets {
    key
    value
  }
}

# VULNERABLE: System information exposure
query {
  systemInfo {
    hostname
    platform
    arch
    version
  }
}
```

**Available Mutations:**

```graphql
# Create a new user
mutation {
  createUser(name: "Alice") {
    id
    name
  }
}

# VULNERABLE: Delete user without authentication
mutation {
  deleteUser(id: 1)
}

# VULNERABLE: Execute arbitrary query
mutation {
  executeQuery(query: "{ users { id } }")
}
```

**Security Issues:**
- Full introspection enabled
- No authentication or authorization
- Secrets exposed via queries
- System information disclosure
- Unrestricted mutations

### Spring Boot Actuator Endpoints

The API mimics Spring Boot Actuator management endpoints with critical vulnerabilities:

- `GET /actuator` - Actuator index (lists all available management endpoints)
- `GET /actuator/health` - Health check with detailed component information
- `GET /actuator/env` - **CRITICAL**: Exposes ALL configuration including secrets, credentials, and environment variables
- `GET /actuator/heapdump` - **CRITICAL**: Simulated heap dump exposing sensitive data from memory
- `POST /actuator/shutdown` - **CRITICAL**: Unauthenticated application shutdown endpoint

**Example Usage:**

```bash
# List all actuator endpoints
curl http://localhost:7341/actuator

# Check application health
curl http://localhost:7341/actuator/health

# VULNERABILITY: Dump all configuration and secrets
curl http://localhost:7341/actuator/env

# VULNERABILITY: Generate heap dump with sensitive data
curl http://localhost:7341/actuator/heapdump

# VULNERABILITY: Shutdown the application without authentication
curl -X POST http://localhost:7341/actuator/shutdown
```

**Security Issues:**
- No authentication or authorization on any endpoint
- Complete environment variable exposure (database passwords, API keys, AWS credentials, JWT secrets, etc.)
- Heap dump contains simulated sensitive data (passwords, tokens, credit cards, private keys)
- Shutdown endpoint allows anonymous DoS attacks
- Detailed system information disclosure
- Production configuration fully exposed

These endpoints simulate common misconfigurations in Spring Boot applications where actuator endpoints are exposed without proper security.

## Testing

Run the test suite:

```bash
cargo test
```

Or use the Makefile:

```bash
make cargo-test
```

## Publishing to Docker Hub

### Prerequisites

1. Docker Hub account
2. Docker installed and logged in (`docker login`)

### Build and Push

Using the Makefile (recommended):

```bash
# Login to Docker Hub
make login

# Build, push, and tag
make publish
```

Or manually:

```bash
# Build the image
docker build -t trapdoorsec/dvwapi:latest -t trapdoorsec/dvwapi:0.1.0 .

# Push to Docker Hub
docker push trapdoorsec/dvwapi:latest
docker push trapdoorsec/dvwapi:0.1.0

# Tag git commit
git tag -a v0.1.0 -m "Release v0.1.0"
git push origin v0.1.0
```

### Available Tags

- `latest` - Latest stable release
- `0.1.0` - Specific version (matches Cargo.toml version)
- Version tags follow semantic versioning

### Environment Variables

Copy `.env.example` to `.env` and customize:

```bash
cp .env.example .env
```

Available variables:
- `DOCKER_REPO` - Docker Hub repository (default: trapdoorsec/dvwapi)
- `TAG` - Image tag (default: latest)
- `HOST_PORT` - Host port mapping (default: 7341)
- `LOG_LEVEL` - Application log level (default: info)

## Makefile Commands

The project includes a Makefile for common operations:

```bash
make help              # Show all available commands
make build             # Build Docker image
make run               # Run container
make stop              # Stop container
make logs              # View container logs
make push              # Push to Docker Hub
make publish           # Build, push, and tag (full release)
make compose-up        # Start with docker-compose
make compose-down      # Stop docker-compose
make cargo-build       # Build Rust binary
make cargo-test        # Run tests
make clean             # Clean up
```

## Security Warning

This application is intentionally vulnerable and should only be used in controlled environments for educational purposes. Do not deploy this on public networks or production systems.

## License

This project is provided as-is for educational purposes only.
