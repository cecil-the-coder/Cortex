# Development Setup Guide

## Quick Start

### Prerequisites

- Go 1.25.3 or later
- Git
- Docker (optional, for containerized deployment)

### Installation

```bash
# Clone the repository
git clone https://github.com/cecil-the-coder/Cortex.git
cd Cortex

# Install dependencies
go mod download
```

### Development Dependencies

This project depends on the `ai-provider-kit` library which is currently in development. To set up local development:

1. **Clone the ai-provider-kit repository:**
   ```bash
   git clone https://github.com/cecil-the-coder/ai-provider-kit.git /path/to/ai-provider-kit
   ```

2. **Update the replace directive in go.mod:**
   ```go
   replace github.com/cecil-the-coder/ai-provider-kit => /path/to/ai-provider-kit
   ```

3. **Run go mod tidy:**
   ```bash
   go mod tidy
   ```

### Building

```bash
# Build for current platform
go build -o cortex ./cmd/router

# Build for multiple platforms
GOOS=linux go build -o cortex-linux ./cmd/router
GOOS=darwin go build -o cortex-macos ./cmd/router
GOOS=windows go build -o cortex.exe ./cmd/router
```

### Configuration

Copy the example configuration file:

```bash
cp config.example.json config.json
```

Set your environment variables:

```bash
export ANTHROPIC_API_KEY="your-anthropic-api-key"
export OPENAI_API_KEY="your-openai-api-key"
export ROUTER_API_KEY="your-router-admin-key"
```

### Running

```bash
# Start the router
./cortex --config config.json

# Start with admin API enabled
./cortex --config config.json --enable-admin

# Start with hot-reload enabled
./cortex --config config.json --hot-reload
```

### Testing

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run specific package tests
go test ./internal/config -v
```

### Docker Development

```bash
# Build development image
docker build --target development -t cortex:dev .

# Run development container
docker run -p 8080:8080 -p 8081:8081 -e CONFIG_PATH=/app/config/config.json cortex:dev
```

### Production Deployment

For production deployment instructions, see the main README.md.

## Troubleshooting

### ai-provider-kit Dependency Issues

If you encounter issues with the ai-provider-kit dependency:

1. Ensure you have the correct version of the ai-provider-kit library
2. Check that the replace directive in go.mod points to the correct local path
3. Run `go mod tidy` to update dependencies

### Build Issues

1. Ensure you have Go 1.25.3 or later
2. Clear Go module cache: `go clean -modcache`
3. Re-download dependencies: `go mod download`

### Configuration Issues

1. Verify your configuration file format is valid JSON
2. Check that all required environment variables are set
3. Ensure API keys are valid and have proper permissions

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

For detailed contribution guidelines, see CONTRIBUTING.md.