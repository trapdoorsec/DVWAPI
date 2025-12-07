# Contributing to DVWAPI

Thank you for your interest in contributing to DVWAPI! This document provides guidelines for contributing to the project.

## Development Setup

### Prerequisites

- Rust 1.86 or later
- Docker (for containerization)
- Make (optional, for convenience commands)

### Local Development

1. Clone the repository:
```bash
git clone https://github.com/trapdoorsec/dvwapi.git
cd DVWAPI
```

2. Build the project:
```bash
cargo build
```

3. Run tests:
```bash
cargo test
```

4. Run the application:
```bash
cargo run -- --log-level debug
```

## Adding New Vulnerabilities

When adding new vulnerabilities, follow these guidelines:

### 1. Documentation

- Add clear comments explaining the vulnerability
- Include exploitation examples in code comments
- Document the endpoint in README.md

### 2. Logging

Add appropriate logging:
- `tracing::debug!()` for normal operations
- `tracing::info!()` for important events
- `tracing::warn!()` for vulnerability access
- `tracing::error!()` for critical vulnerabilities

Example:
```rust
pub async fn vulnerable_endpoint() -> Json<Value> {
    tracing::warn!("VULNERABILITY: endpoint accessed - secrets exposed!");
    // ... implementation
}
```

### 3. Code Structure

Place handlers in appropriate modules:
- `src/handlers/v1.rs` - API v1 endpoints
- `src/handlers/v2.rs` - API v2 endpoints
- `src/handlers/v3.rs` - API v3 endpoints
- `src/handlers/vulnerable.rs` - Intentionally vulnerable endpoints
- `src/graphql.rs` - GraphQL schema and resolvers

### 4. Routes

Add routes in `src/routes.rs`:
```rust
let vulnerable_router = Router::new()
    .route("/vulnerable", get(vulnerable::handler));
```

## Testing

All contributions should include tests:

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_name

# Run with output
cargo test -- --nocapture
```

## Docker

Test Docker builds locally:

```bash
# Build image
make build

# Run container
make run

# Test endpoints
curl http://localhost:7341/

# Stop container
make stop
```

## Publishing Process

### For Maintainers

1. Update version in `Cargo.toml`
2. Update CHANGELOG (if exists)
3. Commit changes:
```bash
git add .
git commit -m "Release v0.x.0"
```

4. Build and publish:
```bash
make publish
```

This will:
- Build the Docker image
- Push to Docker Hub
- Create a git tag
- Push the tag to GitHub

### Manual Publishing

```bash
# Login to Docker Hub
docker login

# Build with version tags
docker build -t trapdoorsec/dvwapi:0.x.0 -t trapdoorsec/dvwapi:latest .

# Push to Docker Hub
docker push trapdoorsec/dvwapi:0.x.0
docker push trapdoorsec/dvwapi:latest

# Tag git commit
git tag -a v0.x.0 -m "Release v0.x.0"
git push origin v0.x.0
```

## GitHub Actions

The project uses GitHub Actions for automated builds:

- Builds on push to main
- Builds on pull requests
- Publishes to Docker Hub on version tags

### Required Secrets

Set these in GitHub repository settings:
- `DOCKERHUB_USERNAME` - Docker Hub username
- `DOCKERHUB_TOKEN` - Docker Hub access token

## Code Style

- Follow Rust standard formatting: `cargo fmt`
- Run clippy for lints: `cargo clippy`
- Keep functions focused and well-documented
- Use descriptive variable names

## Pull Request Process

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run tests: `cargo test`
5. Format code: `cargo fmt`
6. Commit with descriptive message
7. Push to your fork
8. Open a pull request

## Questions or Issues

If you have questions or encounter issues:
- Open a GitHub issue
- Provide detailed information
- Include logs if applicable

## License

By contributing, you agree that your contributions will be licensed under the same license as the project.
