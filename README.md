# DVWAPI

Damn Vulnerable Web API - An intentionally insecure REST API for security testing and training.

> [!WARNING]
> Running this on the open internet will leave the host vulnerable. It is recommended to use the supplied container in a 
> restricted access environment instead. If you choose to host this on the public internet you do so at your own risk!!

## Overview

DVWAPI is a deliberately vulnerable web application designed for learning and practicing web API security testing. It contains common vulnerabilities found in web APIs including exposed sensitive endpoints, lack of authentication, and information disclosure.

## Building

### Native Build

```bash
cargo build --release
```

The compiled binary will be available at `target/release/dvwapi`.

### Docker Build

```bash
docker build -t dvwapi:latest .
```

## Usage

### Native

Run with default settings (0.0.0.0:7341):

```bash
./dvwapi
```

### Docker

Run the container with port mapping:

```bash
docker run -p 7341:7341 dvwapi:latest
```

Run with custom options:

```bash
docker run -p 8080:8080 dvwapi:latest --port 8080 --log-level debug
```

Run in detached mode:

```bash
docker run -d -p 7341:7341 --name dvwapi dvwapi:latest
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
- `GET /api/v3/health` - Health check endpoint
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

## Testing

Run the test suite:

```bash
cargo test
```

## Security Warning

This application is intentionally vulnerable and should only be used in controlled environments for educational purposes. Do not deploy this on public networks or production systems.

## License

This project is provided as-is for educational purposes only.
