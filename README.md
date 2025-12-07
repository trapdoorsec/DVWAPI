# DVWAPI

Damn Vulnerable Web API - An intentionally insecure REST API for security testing and training.

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

### Public Endpoints

- `GET /` - API status
- `GET /users` - List all users
- `GET /users/{id}` - Get user by ID
- `POST /users` - Create new user

### Hidden/Vulnerable Endpoints

- `GET /debug/config` - Exposes sensitive configuration
- `GET /admin` - Admin panel with secrets
- `GET /.env` - Environment file exposure

## Testing

Run the test suite:

```bash
cargo test
```

## Security Warning

This application is intentionally vulnerable and should only be used in controlled environments for educational purposes. Do not deploy this on public networks or production systems.

## License

This project is provided as-is for educational purposes only.
